use proc_macro::TokenStream;
use quote::ToTokens as _;
use syn::{DeriveInput, parse_macro_input};

mod code;

/// Makes an enum with Tuples or Structs in its variants into one with only unit variants. Includes Utoipa TOSchema
#[proc_macro_derive(FlattenEnum, attributes(flatten_enum))]
pub fn flatten_enum(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);

    let input = match code::flatten_enum::Input::as_derive_input(&derive_input) {
        Ok(parsed) => parsed,
        Err(err) => return err.write_errors().into(),
    };

    TokenStream::from(input.into_token_stream())
}
