const path = require("path");
const webpack = require("webpack");
const UglifyJsPlugin = require("uglifyjs-webpack-plugin")

module.exports = {
  entry: {
    "miscreant": "./release/index.js",
    "miscreant.min": "./release/index.js"
  },
  output: {
    path: path.resolve(__dirname, "bundles"),
    filename: "[name].js",
    libraryTarget: "umd",
    library: "miscreant",
    umdNamedDefine: true
  },
  devtool: "source-map",
  plugins: [
    new UglifyJsPlugin({
      sourceMap: true,
      include: /\.min\.js$/,
    })
  ],
  module: {
    rules: [{
        test: /\.js$/,
        use: ["source-map-loader"],
        enforce: "pre"
    }]
  }
}
