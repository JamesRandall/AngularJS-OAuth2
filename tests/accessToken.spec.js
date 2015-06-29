// a test suite (group of tests)
describe('oauth2.accessToken tests', function() {
    beforeEach(module('oauth2.accessToken'));

    it ('can I get an instance of my factory', inject(function(AccessToken) {
        expect(AccessToken).toBeDefined();
    }));

    it ('does the token start as null', inject(function(AccessToken) {
        expect(AccessToken.get()).toBeNull();
    }));
});