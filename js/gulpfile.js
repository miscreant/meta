var gulp = require("gulp");
var ts = require("gulp-typescript");
var sourcemaps = require("gulp-sourcemaps");

var tsProject = ts.createProject("tsconfig.json");

gulp.task("default", function() {
    var tsResult = gulp
        .src(["./src/**/*.ts", "index.ts"])
        .pipe(tsProject());

    return tsResult.js
        .pipe(sourcemaps.write())
        .pipe(gulp.dest("release"));
});
