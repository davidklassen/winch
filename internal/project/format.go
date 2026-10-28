package project

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

// Format fixes the indentation and the step key order of the project files.
// It writes no file when a file fails. It returns the files it changed,
// sorted.
func Format(dir string) ([]string, error) {
	type rewrite struct {
		name, path string
		data       []byte
	}
	var out []rewrite
	var errs []error
	done := map[string]bool{}
	format := func(file string, steps []string) {
		path, err := filepath.EvalSymlinks(projectPath(dir, file))
		if errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, notFound(file))
			return
		}
		if err != nil {
			errs = append(errs, err)
			return
		}
		if done[path] {
			return
		}
		done[path] = true
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("read %s: %w", file, err))
			return
		}
		if _, err := yamlx.Parse(file, data); err != nil {
			errs = append(errs, err)
			return
		}
		formatted, err := yamlx.Format(file, data, steps, stepRank)
		if err != nil {
			errs = append(errs, err)
			return
		}
		if string(formatted) != string(data) {
			out = append(out, rewrite{file, path, formatted})
		}
	}

	// fmt formats a winch.yaml with a schema error.
	if cfg, err := loadConfig(dir); cfg == nil {
		return nil, err
	}
	format("winch.yaml", []string{"steps", "handlers.*", "pipelines.*.steps", "pipelines.*.handlers.*", "pipelines.*.stages.*.steps", "pipelines.*.stages.*.handlers.*", "recipes.*.steps", "recipes.*.handlers.*"})
	invs, err := list(dir, "inventories")
	if err != nil {
		return nil, err
	}
	pipelines, err := list(dir, "pipelines")
	if err != nil {
		return nil, err
	}
	recipes, err := recipeFiles(dir)
	if err != nil {
		return nil, err
	}
	for _, f := range invs {
		format(f, nil)
	}
	for _, f := range pipelines {
		format(f, []string{"steps", "handlers.*", "stages.*.steps", "stages.*.handlers.*"})
	}
	for _, r := range recipes {
		format(r, []string{"steps", "handlers.*"})
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b rewrite) int { return strings.Compare(a.name, b.name) })
	var changed []string
	for _, r := range out {
		if err := replaceFile(r.path, r.data); err != nil {
			return nil, err
		}
		changed = append(changed, r.name)
	}
	return changed, nil
}

// stepRank is the place of a step key in the order of winch fmt. A module key
// takes the place of recipe.
func stepRank(key string) int {
	if i := slices.Index(stepFields, key); i >= 0 {
		return i
	}
	return slices.Index(stepFields, "recipe")
}

// recipeFiles returns the recipe.yaml file of each recipe, relative to dir.
func recipeFiles(dir string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "recipes", "*", "recipe.yaml"))
	if err != nil {
		return nil, err
	}
	var files []string
	for _, p := range paths {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return nil, err
		}
		files = append(files, filepath.ToSlash(rel))
	}
	return files, nil
}
