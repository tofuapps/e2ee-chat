const path = require('path');

module.exports = {
  mode: 'development',
  entry: './src/web/index.ts',
  devtool: 'inline-source-map',
  resolve: {
    extensions: ['.ts', '.js', '.json']
  },
  output: {
    filename: 'app.js',
    path: path.resolve(__dirname, 'dist', 'web'),
  },
  module: {
    rules: [
      { test: /\.ts$/, loader: 'ts-loader' }
    ]
  }
}
