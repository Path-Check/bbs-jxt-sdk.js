const path = require('path');

module.exports = {
  mode: "production",
  entry: "./lib/main.js",
  devtool: "source-map",
  output: {
    filename: 'bbs-jxt.sdk.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'BBS_JXT',
    libraryTarget: 'umd',
  },
  optimization: {
    minimize: false
  }, 
  node: {
    net: 'empty',
  },
};