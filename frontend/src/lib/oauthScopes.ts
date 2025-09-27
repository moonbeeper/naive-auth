const scopeDefinitions: Record<string, string> = {
	USER: 'Get information about your profile',
	USER_EMAIL: 'Be able to see your email address'
};

export const scopesToLegible = (scopes: string[]): string[] => {
	return scopes.map((scope) => {
		if (!scopeDefinitions[scope]) {
			return scope; // return the scope directly is we don't have a description for it
		}
		return scopeDefinitions[scope];
	});
};
