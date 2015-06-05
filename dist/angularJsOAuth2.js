'use strict';

// Move these to a directive
//var authorizationUrl = 'https://localhost:44313/identity/connect/authorize';
//var client_id = 'implicit';
//var redirect_uri = 'http://localhost:37045/';
//var response_type = "token";
//var scope = "extracurricular";
//var state = Date.now() + "" + Math.random();

angular.module('oauth2.accessToken', ['ngStorage']).factory('AccessToken', ['$rootScope', '$location', '$window', '$sessionStorage', function($rootScope, $location, $window, $sessionStorage) {
	var service = {
		token: null
	};
	var oAuth2HashParams = ['access_token', 'token_type', 'expires_in', 'scope', 'state', 'error', 'error_description'];
	
	function setExpiresAt(token) {
		if(token){
            var expires_at = new Date();
            expires_at.setSeconds(expires_at.getSeconds()+parseInt(token.expires_in)-60); // 60 seconds less to secure browser and response latency
            token.expires_at = expires_at;
        }
	}

	function setTokenFromHashParams(hash) {
		var token = getTokenFromHashParams(hash);
		if (token !== null) {
			setExpiresAt(token);
			$sessionStorage.token = token;
		}
		return token;
	}

	function getTokenFromHashParams(hash) {
		var token = {};
        var regex = /([^&=]+)=([^&]*)/g;
        var m;

        while (m = regex.exec(hash)) {
            var param = decodeURIComponent(m[1]);
            var value = decodeURIComponent(m[2]);

            if (oAuth2HashParams.indexOf(param) >= 0) {
              token[param] = value;
            }
        }

        if((token.access_token && token.expires_in) || token.error){
            return token;
        }
        return null;
	}

	service.get = function() {
		return this.token;
	};
	service.set = function() {
		// Try and get the token from the hash params on the URL
		var hashValues = window.location.hash;
		if (hashValues.length > 0) {
			if (hashValues.indexOf('#/') == 0) {
				hashValues = hashValues.substring(2);
			}
			service.token = setTokenFromHashParams(hashValues);
		}
		
		if (service.token === null) {
			service.token = $sessionStorage.token;
			if (service.token === undefined) {
				service.token = null;
			}
		}

		if (service.token && service.token.error) {
			var error = service.token.error;
			service.destroy();
			$rootScope.$broadcast('oauth2:authError', error);
		}

		if (service.token !== null) {
			$rootScope.$broadcast('oauth2:authSuccess');
			if ($sessionStorage.oauthRedirectRoute) {
				var path = $sessionStorage.oauthRedirectRoute;
				$sessionStorage.oauthRedirectRoute = null;
				$location.path(path);
			}
		}
		

		return service.token;
	};
	service.destroy = function() {
		$sessionStorage.token = null;
		delete $sessionStorage.token;
        service.token = null;
	};

	return service;
}]);

// Auth interceptor - if token is missing or has expired this broadcasts an authRequired event
angular.module('oauth2.interceptor', []).factory('OAuth2Interceptor', ['$rootScope', '$q', '$sessionStorage', function ($rootScope, $q, $sessionStorage) {
	var expired = function(token) {
    	return (token && token.expires_at && new Date(token.expires_at) < new Date());
  	};
	
	var service = {
		request: function(config) {
			var token = $sessionStorage.token;
			if (expired(token)) {
				$rootScope.$broadcast('oauth2:authExpired', token);
			}
			else if (token) {
                config.headers.Authorization = 'Bearer ' + token.access_token;
                return config;
			}
    		return config;
  		},
  		response: function(response) {
  			var token = $sessionStorage.token;
  			if (response.status === 401) {
  				if (expired(token)) {
  					$rootScope.$broadcast('oauth2:authExpired', token);
  				} else {
  					$rootScope.$broadcast('oauth2:unauthorized', token);
  				}
  			}
  			else if (response.status === 500) {
  				$rootScope.$broadcast('oauth2:internalservererror');
  			}
  			return response;
  		},
  		responseError: function(response) {
  			var token = $sessionStorage.token;
  			if (response.status === 401) {
  				if (expired(token)) {
  					$rootScope.$broadcast('oauth2:authExpired', token);
  				} else {
  					$rootScope.$broadcast('oauth2:unauthorized', token);
  				}
  			}
  			else if (response.status === 500) {
  				$rootScope.$broadcast('oauth2:internalservererror');
  			}
  			return response;
  		}
	};
  	return service;
}]);

// Endpoint wrapper
angular.module('oauth2.endpoint', []).factory('Endpoint', ['AccessToken', function(accessToken) {
	var service = {
		authorize: function() { window.location.replace(service.url); },
		appendSignoutToken: false
	};

	service.signOut = function(token) {
		if (service.signOutUrl && service.signOutUrl.length > 0) {
			var url = service.signOutUrl;
			if (service.appendSignoutToken) {
				url = url + token;
			}
			window.location.replace(url);
		}
	};
	
	service.init = function(params) {
		service.url = params.authorizationUrl + '?' +
				  	  'client_id=' + encodeURI(params.clientId) + '&' +
				  	  'redirect_uri=' + encodeURI(params.redirectUrl) + '&' +
				  	  'response_type=' + encodeURI(params.responseType) + '&' +
				  	  'scope=' + encodeURI(params.scope) + '&' +
				  	  'state=' + encodeURI(params.state);
		service.signOutUrl = params.signOutUrl;
		
		if (params.signInAppendNonce == 'true') {
			service.url = service.url + '&nonce=' + service.generateNonce(params.signInNonceLength);
		}
		
		if (params.signOutAppendToken == 'true') {
			service.appendSignoutToken = true;
		}
		if (params.signOutRedirectUrl.length > 0) {
			service.signOutUrl = service.signOutUrl+ '?post_logout_redirect_uri=' + encodeURI(params.signOutRedirectUrl);
		}
	};
	
	service.generateNonce = function(length) {
	    var text = "";
	    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	    for(var i = 0; i < length; i++) {
	        text += possible.charAt(Math.floor(Math.random() * possible.length));
	    }
	    return text;
	}

	return service;
}]);

// Open ID directive
angular.module('oauth2.directive', []).directive('oauth2', ['$rootScope', '$http', '$window', '$location', '$templateCache', '$compile', '$sessionStorage', 'AccessToken', 'Endpoint', function($rootScope, $http, $window, $location, $templateCache, $compile, $sessionStorage, accessToken, endpoint) {
	var definition = {
	    restrict: 'E',
	    replace: true,
	    scope: {
			authorizationUrl: '@',          // authorization server url
			clientId: '@',       			// client ID
			redirectUrl: '@',   			// uri th auth server should redirect to (cannot contain #)
			responseType: '@',  			// defaults to token
			scope: '@',						// scopes required (not the Angular scope - the auth server scopes)
			state: '@',						// state to use for CSRF protection
			template: '@',					// path to a replace template for the button, defaults to the one supplied by bower
			buttonClass: '@',				// the class to use for the sign in / out button - defaults to btn btn-primary
			signInText: '@',				// text for the sign in button
			signOutText: '@',				// text for the sign out button
			signOutUrl: '@',				// url on the authorization server for logging out. Local token is deleted even if no URL is given but that will leave user logged in against STS
			signOutAppendToken: '@',		// defaults to 'false', set to 'true' to append the token to the sign out url
			signOutRedirectUrl: '@',		// url to redirect to after sign out on the STS has completed
			signInAppendNonce: '@',			// whether to append a nonce or not
			signInNonceLength: '@'			// the length of the nonce (only used if signInAppendNonce is set - defaults to 8 chars if not set)
	    }
	};

	definition.link = function(scope, element, attrs) {
		function compile() {
			var tpl = '<p class="navbar-btn"><a class="{{buttonClass}}"><span href="#" ng-hide="signedIn" ng-click="signIn()" >{{signInText}}</span><span href="#" ng-show="signedIn" ng-click="signOut()">{{signOutText}}</span></a></p>';
			if (scope.template) {
				$http.get(scope.template, { cache: $templateCache }).success(function(html) {
		        element.html(html);
		        $compile(element.contents())(scope);
		      });
			} else {
				element.html(tpl);
				$compile(element.contents())(scope);
			}
	    };

	    function routeChangeHandler(event, nextRoute) {
	    	if (nextRoute.$$route && nextRoute.$$route.requireToken) {
                if (!accessToken.get()) {
                	event.preventDefault();
                	$sessionStorage.oauthRedirectRoute = $location.path();
                    endpoint.authorize();
                }
            }
	    };

		function init() {
			scope.buttonClass = scope.buttonClass || 'btn btn-primary';
			scope.signInText = scope.signInText || 'Sign In';
			scope.signOutText = scope.signOutText || 'Sign Out';
			scope.responseType = scope.responseType || 'token';
			scope.signOutUrl = scope.signOutUrl || '';
			scope.signOutRedirectUrl = scope.signOutRedirectUrl || '';
			scope.unauthorizedAccessUrl = scope.unauthorizedAccessUrl || '';
			scope.signInAppendNonce = scope.signInAppendNonce || '';
			
			if (scope.signInNonceLength !== '' && !isNaN(scope.signInNonceLength)) {
			    scope.signInNonceLength = scope.signInNonceLength;
			}
			else {
				scope.signInNonceLength = 8;
			}

			compile();

			endpoint.init(scope);
			scope.signedIn = accessToken.set() !== null;
			scope.$on('oauth2:authRequired', function() {
				endpoint.authorize();
			});
			scope.$on('oauth2:authError', function() {
				if (scope.unauthorizedAccessUrl.length > 0) {
					$location.path(scope.unauthorizedAccessUrl);
				}
			});
			scope.$on('oauth2:authExpired', function() {
				scope.signedIn = false;
			});
			$rootScope.$on('$routeChangeStart', routeChangeHandler);
		}

		scope.$watch('clientId', function(value) { init(); });

		scope.signedIn = false;

		scope.signIn = function() {
			endpoint.authorize();
		}

		scope.signOut = function() {
			var token = accessToken.get().access_token;
			accessToken.destroy();
			endpoint.signOut(token);
		};
	};

	return definition;
}]);

// App libraries
angular.module('afOAuth2', [
  'oauth2.directive',      // login directive
  'oauth2.accessToken',    // access token service
  'oauth2.endpoint',       // oauth endpoint service
  'oauth2.interceptor'     // bearer token interceptor
]).config(['$locationProvider','$httpProvider',
	function($locationProvider, $httpProvider) {
		$httpProvider.interceptors.push('OAuth2Interceptor');
	}
]);