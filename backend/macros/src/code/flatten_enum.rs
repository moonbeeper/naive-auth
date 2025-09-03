use darling::{FromDeriveInput, FromVariant};
use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, quote};
use syn::Ident;

#[derive(Debug, FromDeriveInput)]
#[darling(supports(enum_any), attributes(flatten_enum))]
pub struct Input {
    pub ident: syn::Ident,
    pub data: darling::ast::Data<EnumVariant, darling::util::Ignored>,

    #[darling(default)]
    pub utoipa_name: Option<String>,
    #[darling(skip)]
    pub variants: Vec<EnumVariant>,
}

#[derive(Debug, FromVariant, Clone)]
pub struct EnumVariant {
    pub ident: syn::Ident,
    pub fields: darling::ast::Fields<()>,
}

// probably shouldn't be doing these things this way but womp
impl Input {
    pub fn as_derive_input(input: &syn::DeriveInput) -> darling::Result<Self> {
        let mut this = Self::from_derive_input(input)?;

        let variants: Vec<_> = this.data.clone().take_enum().unwrap();
        this.variants = variants;
        Ok(this)
    }
}

impl ToTokens for Input {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let root_ident = &self.ident;
        let new_ident = Ident::new(&format!("{}Flattened", root_ident), root_ident.span());
        let variants: Vec<_> = self.variants.iter().map(|v| &v.ident).collect();

        let mut arms: Vec<_> = Vec::new();

        for variant in &self.variants {
            let ident = &variant.ident;
            let params = if variant.fields.is_unit() {
                quote! {}
            } else if variant.fields.is_tuple() {
                quote! { (..)}
            } else if variant.fields.is_struct() {
                quote! { { .. } }
            } else {
                unreachable!("how the hell did this happen?")
            };

            arms.push(quote! {
                #root_ident::#ident #params => #new_ident::#ident
            })
        }

        let utoipa_schema = if let Some(name) = &self.utoipa_name {
            let ident = Ident::new(&name, Span::call_site());
            quote! {
                #[schema(as = #ident)]
            }
        } else {
            quote! {}
        };

        tokens.extend(quote! {
            #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
            #utoipa_schema
            #[automatically_derived] // thiserror adds this
            pub enum #new_ident {
                #(#variants,)*
            }

            #[automatically_derived]
            impl From<#root_ident> for #new_ident {
                fn from(value: #root_ident) -> Self {
                    match value {
                        #(#arms,)*
                    }
                }
            }
        });
    }
}
