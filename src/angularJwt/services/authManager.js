(function(window, angular, undefined) {
	'use strict';


	angular.module('angular-jwt.jwtAuthManager', [])
	.constant('JWT_AUTH_EVENTS', {
		sessionTimeout: 'jwt.tokenHasExpired',
		authenticated: 'jwt.authenticated',
		notAuthenticated: 'jwt.notAuthenticated'
	})
	.provider('jwtAuthManager', function () {
		var _isAuthenticated = false;

		this.$get = function ($rootScope, $injector, $location, jwtHelper, jwtInterceptor, jwtOptions, JWT_AUTH_EVENTS) {

			var config = jwtOptions.getConfig();

			function invokeToken(tokenGetter) {
				var token = null;
				if (Array.isArray(tokenGetter)) {
					token = $injector.invoke(tokenGetter, this, {options: null});
				} else {
					token = tokenGetter();
				}
				return token;
			}

			function invokeRedirector( redirector, nextState, params ) {
				console.log( 'NEXT STATE', nextState, params);
				if (Array.isArray(redirector) || angular.isFunction(redirector)) {
					return $injector.invoke(redirector, config, { next: nextState, params: params });
				} else {
					throw new Error('unauthenticatedRedirector must be a function');
				}
			}

			function isAuthenticated() {
				var token = invokeToken(config.tokenGetter);
				if (token) {
					return !jwtHelper.isTokenExpired(token);
				}
				return false;
			}

			function authenticate() {
				_isAuthenticated = true;
			}

			function unauthenticate() {
				_isAuthenticated = false;
			}

			function checkAuthOnRefresh() {
				$rootScope.$on('$locationChangeStart', function () {
					var token = invokeToken(config.tokenGetter);
					if (token) {
						if (!jwtHelper.isTokenExpired(token)) {
							authenticate();
							$rootScope.$broadcast( JWT_AUTH_EVENTS.authenticated, token );
						} else {
							$rootScope.$broadcast( JWT_AUTH_EVENTS.sessionTimeout, token );
						}
					}
				});
			}

			function redirectWhenUnauthenticated() {
				$rootScope.$on( JWT_AUTH_EVENTS.notAuthenticated, function () {
					invokeRedirector(config.unauthenticatedRedirector);
					unauthenticate();
				});
			}

			function verifyRoute(event, next, params) {
				console.warn( 'Verifying Route', next, params, isAuthenticated() );
				if (!next) {
					return false;
				}

				var routeData = (next.$$route) ? next.$$route : next.data;

				if (routeData && routeData.requiresLogin === true) {
					if ( !isAuthenticated() ) {
						event.preventDefault();
						invokeRedirector( config.unauthenticatedRedirector, next, params );
					}
				}
			}

			var eventName = ($injector.has('$state')) ? '$stateChangeStart' : '$routeChangeStart';
			$rootScope.$on(eventName, verifyRoute);

			return {
				authenticate: authenticate,
				unauthenticate: unauthenticate,
				getToken: function(){ return invokeToken(config.tokenGetter); },
				redirect: function( evt, next, params) { return invokeRedirector(config.unauthenticatedRedirector, next, params); },
				checkAuthOnRefresh: checkAuthOnRefresh,
				redirectWhenUnauthenticated: redirectWhenUnauthenticated,
				isAuthenticated: isAuthenticated
			};
		};
	});
})(window, window.angular);
