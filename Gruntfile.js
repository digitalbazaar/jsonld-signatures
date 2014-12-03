/*
 * jsonld-signatures Gruntfile.
 *
 * Copyright (c) 2014 Digital Bazaar, Inc. All rights reserved.
 */
module.exports = function(grunt) {
  'use strict';

  // init config
  grunt.initConfig({});

  // optimization flag (any require.js mode, ie, 'uglify', 'none', etc
  grunt.config('optimize',
    grunt.option('optimize') || process.env.GRUNT_OPTIMIZE || 'uglify');

  // read package configuration
  grunt.config('pkg', grunt.file.readJSON('package.json'));

  // grunt-mocha-test
  grunt.loadNpmTasks('grunt-mocha-test');
  grunt.config('mochaTest', {
    test: {
      options: {
        reporter: 'spec'
      },
      src: ['tests/test.js']
    }
  });

  // grunt shell
  grunt.loadNpmTasks('grunt-shell');
  grunt.config('shell', {
    testBrowser: {
      command: './node_modules/.bin/phantomjs tests/test.js'
    },
    coverage: {
      command: './node_modules/.bin/istanbul cover ' +
        './node_modules/.bin/_mocha -- -u exports -R spec tests/test.js'
    }
  });

  // grunt release
  grunt.loadNpmTasks('grunt-release');
  grunt.config('release', {
    options: {
      additionalFiles: 'bower.json',
      commitMessage: 
        'Tag version <%= version %> for release to npmjs.org and bower.'
  }});

  // _jshint
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.config('jshint', {
    all: {
      src: [
       'lib/*.js',
       'bin/jsigs',
       'tests/*.js'
      ]
    }
  });

  // default tasks
  grunt.registerTask('default', ['mochaTest']);
};
