var gulp = require("gulp");
var ts = require("gulp-typescript");
var sourcemaps = require("gulp-sourcemaps");
var webpack = require("webpack-stream");
var webpackConfig = require("./webpack.config.js");

var tsProject = ts.createProject("tsconfig.json");

gulp.task("default", () => {
    var tsResult = gulp
        .src(["./src/**/*.ts", "index.ts"])
        .pipe(tsProject());

    return tsResult.js
        .pipe(sourcemaps.write())
        .pipe(gulp.dest("release"));
});

gulp.task("webpack", ["default"], () => {
    gulp.src("./release/index.js")
        .pipe(webpack(webpackConfig))
        .pipe(gulp.dest("bundle"));
});
