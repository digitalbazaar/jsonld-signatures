module.exports = function(config) {
  const bundler = process.env.BUNDLER || 'webpack';
  const frameworks = ['mocha', 'chai'];

  const files = ['unit/*.js'];

  // browser launchers: https://npmjs.org/browse/keyword/karma-launcher
  // browsers: ['ChromeHeadless', 'Chrome', 'Firefox', 'Safari'],
  const browsers = ['ChromeHeadless'];

  const reporters = ['mocha'];
  const client = {
    mocha: {
      timeout: 10000, // 10 sec
      reporter: 'html'
      //delay: true
    }
  };

  // main bundle preprocessors
  const preprocessors = [];
  preprocessors.push(bundler);
  preprocessors.push('sourcemap');

  return config.set({
    frameworks,
    files,
    reporters,
    basePath: '',
    port: 9876,
    colors: true,
    browsers,
    client,

    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR ||
    //   config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,

    singleRun: true,

    // enable / disable watching file and executing tests whenever any
    // file changes
    autoWatch: false,

    // preprocess matching files before serving them to the browser
    // available preprocessors:
    // https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
      'unit/*.js': preprocessors,
    },

    webpack: {
      devtool: 'inline-source-map',
      mode: 'development',
      node: {
        Buffer: false,
        crypto: false,
        setImmediate: false,
        util: false
      }
    }
  });
};
