'use strict';

(function() {
    var tokenStorage = {
        get: function($window) { return $window.sessionStorage.getItem('token') },
        set: function(token, $window) { $window.sessionStorage.setItem('token', token); },
        clear: function($window) { $window.sessionStorage.removeItem('token'); }
    };
    
	function expired(token) {
		return (token && token.expires_at && new Date(token.expires_at) < new Date());
	};
	function getSessionToken($window) {
		var tokenString = tokenStorage.get($window);
		var token = null;
		if (tokenString && tokenString !== "null" ) {
			token = JSON.parse(tokenString);
			token.expires_at= new Date(token.expires_at);
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
                tokenStorage.set(JSON.stringify(token), $window)	
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
		service.set = function(trustedTokenHash) {
			// Get and scrub the session stored state
			var parsedFromHash = false;
			var previousState = $window.sessionStorage.getItem('verifyState');
			$window.sessionStorage.setItem('verifyState', null);

			if(trustedTokenHash) {
				// We 'trust' this hash as it was already 'parsed' by the child iframe before we got it as the parent
				// and then handed it back (not just reverifying as the sessionStorage was blanked by the child frame, so
				// we can't :(
				service.token = setTokenFromHashParams(trustedTokenHash);
			}
			else if ($location.$$html5) {
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
					if (typeof(oauthRedirectRoute) !== 'undefined' && oauthRedirectRoute != "null") {
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
            tokenStorage.clear($window)
			$window.sessionStorage.setItem('token', null);
			service.token = null;
		};

		return service;
	}]);

	// Auth interceptor - if token is missing or has expired this broadcasts an authRequired event
	angular.module('oauth2.interceptor', []).factory('OAuth2Interceptor', ['$rootScope', '$q', '$window',  function ($rootScope, $q, $window) {
		
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
	angular.module('oauth2.endpoint', ['angular-md5']).factory('Endpoint', ['AccessToken', '$window', 'md5', '$rootScope', function(accessToken, $window, md5, $rootScope) {
		var service = {
			authorize: function() {
				accessToken.destroy();
				$window.sessionStorage.setItem('verifyState', service.state);
				window.location.replace(getAuthorizationUrl());
			},
			appendSignoutToken: false
		};

		function getAuthorizationUrl(performSilently) {
			var url= service.authorizationUrl + '?' +
							  'client_id=' + encodeURIComponent(service.clientId) + '&' +
							  'redirect_uri=' + encodeURIComponent(performSilently?service.silentTokenRedirectUrl:service.redirectUrl) + '&' +
							  'response_type=' + encodeURIComponent(service.responseType) + '&' +
							  'scope=' + encodeURIComponent(service.scope);
			if (service.nonce) {
				url += '&nonce=' + encodeURIComponent(service.nonce);
			}
			url += '&state=' + encodeURIComponent(service.state);

			if( performSilently ) {
				url = url + "&prompt=none";
			}
			return url;
		}

		service.renewTokenSilently= function() {
			function setupTokenSilentRenewInTheFuture() {
					var frame= $window.document.createElement("iframe");
					frame.style.display = "none";
					$window.sessionStorage.setItem('verifyState', service.state);
					frame.src= getAuthorizationUrl(true);
					function cleanup() {
						$window.removeEventListener("message", message, false);
						if( handle) {
							window.clearTimeout(handle);
						}
						handle= null;
						$window.setTimeout(function() {
							// Complete this on another tick of the eventloop to allow angular (in the child frame) to complete nicely.
							$window.document.body.removeChild(frame);
						}, 0);
					}

					function message(e) {
						if (handle && e.origin === location.protocol + "//" + location.host && e.source == frame.contentWindow) {
							cleanup();
							if( e.data === "oauth2.silentRenewFailure" ) {
								$rootScope.$broadcast('oauth2:authExpired');
							}
							else {
								accessToken.set(e.data);
							}
						}
					}

					var handle= window.setTimeout(function() {
						cleanup();
					}, 5000);
					$window.addEventListener("message", message, false);
					$window.document.body.appendChild(frame);
			};

			var now= new Date();
			// Renew the token 1 minute before we expect it to expire. N.B. This code elsewhere sets the expires_at to be 60s less than the server-decided expiry time
			// this has the effect of reducing access token lifetimes by a mininum of 2 minutes, and restricts you to producing access tokens that are at *least* this long lived

			var renewTokenAt= new Date( accessToken.get().expires_at.getTime() - 60000 );
			var renewTokenIn= renewTokenAt - new Date();
			window.setTimeout(setupTokenSilentRenewInTheFuture, renewTokenIn);
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
			function generateState() {
				var text = ((Date.now() + Math.random()) * Math.random()).toString().replace(".","");
				return md5.createHash(text);
			}

			if (!params.nonce && params.autoGenerateNonce) {
			  params.nonce = generateState();
			}
			service.nonce = params.nonce;
			service.clientId= params.clientId;
			service.redirectUrl= params.redirectUrl;
			service.scope= params.scope;
			service.responseType= params.responseType;
			service.authorizationUrl= params.authorizationUrl;
			service.signOutUrl = params.signOutUrl;
			service.silentTokenRedirectUrl= params.silentTokenRedirectUrl;
			service.signOutRedirectUrl = params.signOutRedirectUrl;
			service.state = params.state || generateState();
			if (params.signOutAppendToken == 'true') {
				service.appendSignoutToken = true;
			}
		};

		return service;
	}]);

	// Open ID directive
	angular.module('oauth2.directive', [])
		.config(['$routeProvider', function ($routeProvider) {
			$routeProvider
				.when('/silent-renew', {
					template: ""
				})
		}])
		.directive('oauth2', ['$rootScope', '$http', '$window', '$location', '$templateCache', '$compile', 'AccessToken', 'Endpoint', function($rootScope, $http, $window, $location, $templateCache, $compile, accessToken, endpoint) {
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
                    silentTokenRedirectUrl: '@',	// url to use for silently renewing access tokens, default behaviour is not to do
                    nonce: '@?',					// nonce value, optional. If unspecified or an empty string and autoGenerateNonce is true then a nonce will be auto-generated
                    autoGenerateNonce: '=?',	    // Should a nonce be autogenerated if not supplied. Optional and defaults to true.
                    tokenStorageHandler: '='
				}
			};

		definition.link = function(scope, element, attrs) {
			function compile() {
				var tpl = '<p class="navbar-btn"><a class="{{buttonClass}}" ng-click="signedIn ? signOut() : signIn()"><span href="#" ng-hide="signedIn">{{signInText}}</span><span href="#" ng-show="signedIn">{{signOutText}}</span></a></p>';
				if (scope.template) {
					$http.get(scope.template, { cache: $templateCache }).then(function(templateResult) {
			        	element.html(templateResult.data);
			        	$compile(element.contents())(scope);
			      	});
				} else {
					element.html(tpl);
					$compile(element.contents())(scope);
				}
		    };

		    function routeChangeHandler(event, nextRoute) {
		    	if (nextRoute.$$route && nextRoute.$$route.requireToken) {
	                if (!accessToken.get() || expired(accessToken.get())) {
	                	event.preventDefault();
	                	$window.sessionStorage.setItem('oauthRedirectRoute', $location.path());
	                    endpoint.authorize();
	                }
	            }
		    };


			function init() {
                if (scope.tokenStorageHandler) {
                    tokenStorage = scope.tokenStorageHandler
                }
				scope.buttonClass = scope.buttonClass || 'btn btn-primary';
				scope.signInText = scope.signInText || 'Sign In';
				scope.signOutText = scope.signOutText || 'Sign Out';
				scope.responseType = scope.responseType || 'token';
				scope.signOutUrl = scope.signOutUrl || '';
				scope.signOutRedirectUrl = scope.signOutRedirectUrl || '';
				scope.unauthorizedAccessUrl = scope.unauthorizedAccessUrl || '';
				scope.silentTokenRedirectUrl = scope.silentTokenRedirectUrl || '';
				if (scope.autoGenerateNonce === undefined) {
					scope.autoGenerateNonce = true;
				}
				compile();

				endpoint.init(scope);
				scope.$on('oauth2:authRequired', function() {
					endpoint.authorize();
				});
				scope.$on('oauth2:authSuccess', function() {
					if (scope.silentTokenRedirectUrl.length > 0) {
						if( $location.path().indexOf("/silent-renew") == 0 ) {
							// A 'child' frame has successfully authorised an access token.
							if (window.top && window.parent && window !== window.top) {
								var hash = hash || window.location.hash;
								if (hash) {
									window.parent.postMessage(hash, location.protocol + "//" + location.host);
								}
							}
						} else {
							// An 'owning' frame has successfully authorised an access token.
							endpoint.renewTokenSilently();
						}
					}
				});
				scope.$on('oauth2:authError', function() {
					if( $location.path().indexOf("/silent-renew") == 0 && window.top && window.parent && window !== window.top) {
						// A 'child' frame failed to authorize.
						window.parent.postMessage("oauth2.silentRenewFailure", location.protocol + "//" + location.host);
					}
					else {
						if (scope.unauthorizedAccessUrl.length > 0) {
							$location.path(scope.unauthorizedAccessUrl);
						}
					}
				});
				scope.$on('oauth2:authExpired', function() {
					scope.signedIn = false;
					accessToken.destroy();
				});
				scope.signedIn = accessToken.set() !== null;
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
