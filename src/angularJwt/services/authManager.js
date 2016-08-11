angular.module('angular-jwt.authManager', [])
  .provider('authManager', function() {

    this.authenticated = false;
    this.loginPath = '/';
    this.tokenGetter = function() {
      return null;
    }
    this.unauthenticatedRedirector = function(location) {
      location.path(this.loginPath);
    }

    var config = this;

    this.$get = function($rootScope, $location, jwtHelper, jwtInterceptor) {

      var authenticated = false;

      function isAuthenticated() {
        return authenticated;
      }

      function checkAuthOnRefresh() {
        var routerEvent = '$locationChangeStart';
        $rootScope.$on(routerEvent, function() {
          var token = config.tokenGetter();
          if (token) {
            if (!jwtHelper.isTokenExpired(token)) {
              authenticated = true;
            }
          } else {
            authenticated = false;
            config.unauthenticatedRedirector($location);
          }
        });
      }
      
      function redirectWhenUnauthenticated() {
        $rootScope.$on('unauthenticated', function() {
          config.unauthenticatedRedirector($location);
        });
      }

      return {
        isAuthenticated: isAuthenticated,
        checkAuthOnRefresh: checkAuthOnRefresh,
        redirectWhenUnauthenticated: redirectWhenUnauthenticated
      }
    }
  });