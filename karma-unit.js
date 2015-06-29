var grunt = require('grunt');
module.exports = function ( karma ) {
  karma.set({
    
    basePath: '.',

    files: [
      "http://code.angularjs.org/1.4.1/angular.js",
      "http://code.angularjs.org/1.4.1/angular-mocks.js",
      "dist/angularJsOAuth2.js",
      "tests/*.spec.js",
    ],

    frameworks: [ 'jasmine' ],
    
    logLevel: karma.LOG_INFO,

    reporters: ['progress'],

    port: 7019,

    autoWatch: true,

    browsers: [
      'PhantomJS'
    ],

    singleRun: false
  });
};