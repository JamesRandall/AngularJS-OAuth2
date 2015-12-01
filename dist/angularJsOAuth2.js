'use strict';

// Move these to a directive
//var authorizationUrl = 'https://localhost:44313/identity/connect/authorize';
//var client_id = 'implicit';
//var redirect_uri = 'http://localhost:37045/';
//var response_type = "token";
//var scope = "extracurricular";
//var state = Date.now() + "" + Math.random();

(function() {
	function getSessionToken($window) {
		var tokenString = $window.sessionStorage.getItem('token');
		var token = null;
		if (tokenString) {
			token = JSON.parse(tokenString);
		}
		return token;
	}

	angular.module('oauth2.accessToken', []).factory('AccessToken', ['$rootScope', '$location', '$window', function($rootScope, $location, $window) {
		var service = {
			token: null
		};
		var oAuth2HashParams = ['id_token', 'access_token', 'token_type', 'expires_in', 'scope', 'state', 'error', 'error_description'];

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
				$window.sessionStorage.setItem('token', JSON.stringify(token));
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
			// Get and scrub the session stored state
			var parsedFromHash = false;
			var previousState = $window.sessionStorage.getItem('verifyState');
			$window.sessionStorage.setItem('verifyState', null);

			if ($location.$$html5) {
				if ($location.path().length > 1) {
					var values = $location.path().substring(1);
					service.token = setTokenFromHashParams(values);
					if (service.token) {
						parsedFromHash = true;
					}
				}
			} else {
				// Try and get the token from the hash params on the URL
				var hashValues = window.location.hash;
				if (hashValues.length > 0) {
					if (hashValues.indexOf('#/') == 0) {
						hashValues = hashValues.substring(2);
					}
					service.token = setTokenFromHashParams(hashValues);
					if (service.token) {
						parsedFromHash = true;
					}
				}
			}
			
			if (service.token === null) {			
				service.token = getSessionToken($window);
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
				if (!parsedFromHash || previousState == service.token.state) {
					$rootScope.$broadcast('oauth2:authSuccess', service.token);
					var oauthRedirectRoute = $window.sessionStorage.getItem('oauthRedirectRoute');
					if (oauthRedirectRoute && oauthRedirectRoute != "null") {
						$window.sessionStorage.setItem('oauthRedirectRoute', null);
						$location.path(oauthRedirectRoute);
					}
				}
				else {
					service.destroy();
					$rootScope.$broadcast('oauth2:authError', 'Suspicious callback');
				}
			}
			

			return service.token;
		};
		service.destroy = function() {
			$window.sessionStorage.setItem('token', null);
	        service.token = null;
		};

		return service;
	}]);

	// Auth interceptor - if token is missing or has expired this broadcasts an authRequired event
	angular.module('oauth2.interceptor', []).factory('OAuth2Interceptor', ['$rootScope', '$q', '$window',  function ($rootScope, $q, $window) {
		var expired = function(token) {
	    	return (token && token.expires_at && new Date(token.expires_at) < new Date());
	  	};
		
		var service = {
			request: function(config) {
				var token = getSessionToken($window);
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
	  			var token = getSessionToken($window);
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
	  			var token = getSessionToken($window);
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
	  			return $q.reject(response);
	  		}
		};
	  	return service;
	}]);

	// Endpoint wrapper
	angular.module('oauth2.endpoint', []).factory('Endpoint', ['AccessToken', '$window', function(accessToken, $window) {
		var service = {
			authorize: function() {
				$window.sessionStorage.setItem('verifyState', service.state);
				window.location.replace(service.url);
			},
			appendSignoutToken: false
		};

		service.signOut = function(token) {
			if (service.signOutUrl && service.signOutUrl.length > 0) {
				var url = service.signOutUrl;
				if (service.appendSignoutToken) {
					url = url + '?id_token_hint=' + token;
				}
				if (service.signOutRedirectUrl && service.signOutRedirectUrl.length > 0) {
					url = url + (service.appendSignoutToken ? '&' : '?');
					url = url + 'post_logout_redirect_uri=' + encodeURIComponent(service.signOutRedirectUrl);
				}
				window.location.replace(url);
			}
		};
		
		service.init = function(params) {
			service.url = params.authorizationUrl + '?' +
					  	  'client_id=' + encodeURIComponent(params.clientId) + '&' +
					  	  'redirect_uri=' + encodeURIComponent(params.redirectUrl) + '&' +
					  	  'response_type=' + encodeURIComponent(params.responseType) + '&' +
					  	  'scope=' + encodeURIComponent(params.scope) + '&';
			if (params.nonce) {
				service.url += 'nonce=' + encodeURIComponent(params.nonce) + '&';
			}
			service.url += 'state=' + encodeURIComponent(params.state);
			service.signOutUrl = params.signOutUrl;
			service.signOutRedirectUrl = params.signOutRedirectUrl;
			service.state = params.state;
			if (params.signOutAppendToken == 'true') {
				service.appendSignoutToken = true;
			}
		};

		return service;
	}]);

	// Open ID directive
	angular.module('oauth2.directive', ['angular-md5']).directive('oauth2', ['$rootScope', '$http', '$window', '$location', '$templateCache', '$compile', 'AccessToken', 'Endpoint', 'md5', function($rootScope, $http, $window, $location, $templateCache, $compile, accessToken, endpoint, md5) {
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
				nonce: '@?',					// nonce value, optional. If unspecified or an empty string and autoGenerateNonce is true then a nonce will be auto-generated
				autoGenerateNonce: '=?'		    // Should a nonce be autogenerated if not supplied. Optional and defaults to true.
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
	                	$window.sessionStorage.setItem('oauthRedirectRoute', $location.path());
	                    endpoint.authorize();
	                }
	            }
		    };

		    function generateState() {
				var text = ((Date.now() + Math.random()) * Math.random()).toString().replace(".","");
				return md5.createHash(text);
			}

			function init() {
				scope.buttonClass = scope.buttonClass || 'btn btn-primary';
				scope.signInText = scope.signInText || 'Sign In';
				scope.signOutText = scope.signOutText || 'Sign Out';
				scope.responseType = scope.responseType || 'token';
				scope.signOutUrl = scope.signOutUrl || '';
				scope.signOutRedirectUrl = scope.signOutRedirectUrl || '';
				scope.unauthorizedAccessUrl = scope.unauthorizedAccessUrl || '';
				scope.state = scope.state || generateState();
				if (scope.autoGenerateNonce === undefined) {
					scope.autoGenerateNonce = true;
				}
				if (!scope.nonce && scope.autoGenerateNonce) {
					scope.nonce = generateState();
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
				$window.sessionStorage.setItem('oauthRedirectRoute', $location.path());
				endpoint.authorize();
			}

			scope.signOut = function() {
				var token = accessToken.get().id_token;
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
})();
