// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package onixctl

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Builder is responsible for building plugins and images.
type Builder struct {
	config        *Config
	workspacePath string
	outputPath    string
	runner        CommandRunner
}

type CommandRunner interface {
    Run(cmd *exec.Cmd) error
}

type OSCommandRunner struct{}

// Run executes the given command.
func (r *OSCommandRunner) Run(cmd *exec.Cmd) error {
	return cmd.Run()
}

// NewBuilder creates a new Builder.
func NewBuilder(config *Config, workspacePath string) (*Builder, error) {
	// Ensure output directory exists
	outputPath, err := filepath.Abs(config.Output)
	if err != nil {
		return nil, fmt.Errorf("could not get absolute path for output directory: %w", err)
	}
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	return &Builder{
		config:        config,
		workspacePath: workspacePath,
		outputPath:    outputPath,
		runner:        &OSCommandRunner{}, // CHANGED: Initialize the default runner
	}, nil
}

// Build orchestrates the entire build process.
func (b *Builder) Build() error {
	// 1. Build plugins in Docker
	fmt.Println("Starting plugin build process inside Docker...")
	if err := b.buildPluginsInDocker(); err != nil {
		return err
	}

	// 2. Build images locally
	fmt.Println("Starting local image build process...")
	if err := b.buildImagesLocally(); err != nil {
		return err
	}

	fmt.Println("✅ Build process completed successfully.")
	return b.zipAndCopyPlugins()
}

// buildPluginsInDocker builds the Go plugins inside a Docker container.
func (b *Builder) buildPluginsInDocker() error {
	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	script.WriteString("set -e\n")
	script.WriteString("export GOOS=linux\n")
	script.WriteString("export GOARCH=amd64\n")
	script.WriteString("echo '--- Starting plugin build script ---\n'")

	pluginOutputDir := "/workspace/plugins_out"
	script.WriteString(fmt.Sprintf("mkdir -p %s\n", pluginOutputDir))

	for _, module := range b.config.Modules {
		modulePath := filepath.Join("/workspace", module.DirName)
		for id, pluginPath := range module.Plugins {
			fullPluginPath := filepath.Join(modulePath, pluginPath)
			outputFile := filepath.Join(pluginOutputDir, fmt.Sprintf("%s.so", id))
			cmd := fmt.Sprintf("echo 'Building plugin %s...' && go build -buildmode=plugin -buildvcs=false -o %s %s\n", id, outputFile, fullPluginPath)
			script.WriteString(cmd)
		}
	}
	script.WriteString("echo '--- Plugin build script finished ---\n'")

	scriptPath := filepath.Join(b.workspacePath, "build_plugins.sh")
	if err := os.WriteFile(scriptPath, []byte(script.String()), 0755); err != nil {
		return fmt.Errorf("failed to write plugin build script: %w", err)
	}

	cmd := exec.Command("docker", "run", "--rm",
	    "--platform", "linux/amd64",
		"-v", fmt.Sprintf("%s:/workspace", b.workspacePath),
		"-w", "/workspace",
		fmt.Sprintf("golang:%s-bullseye", b.config.GoVersion),
		"sh", "./build_plugins.sh",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return b.runner.Run(cmd)
}

// buildImagesLocally builds the Docker images on the host machine.
func (b *Builder) buildImagesLocally() error {
	for _, module := range b.config.Modules {
		if len(module.Images) > 0 {
			moduleWorkspacePath := filepath.Join(b.workspacePath, module.DirName)
			for name, image := range module.Images {
				imageName := fmt.Sprintf("%s:%s", name, image.Tag)
				if b.config.Registry != "" {
					imageName = fmt.Sprintf("%s/%s:%s", b.config.Registry, name, image.Tag)
				}

				dockerfilePath := filepath.Join(moduleWorkspacePath, image.Dockerfile)
				dockerfileDir := filepath.Dir(dockerfilePath)
				dockerfileName := filepath.Base(dockerfilePath)

				fmt.Printf("Building image %s for platform linux/amd64...\n", imageName)
				cmd := exec.Command("docker", "buildx", "build", "--platform", "linux/amd64", "--load", "-t", imageName, "-f", dockerfileName, ".")
				cmd.Dir = dockerfileDir
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := b.runner.Run(cmd); err != nil {
					return fmt.Errorf("failed to build image %s: %w", imageName, err)
				}

				if b.config.Registry != "" {
					fmt.Printf("Pushing image %s...\n", imageName)
					cmdPush := exec.Command("docker", "push", imageName)
					cmdPush.Stdout = os.Stdout
					cmdPush.Stderr = os.Stderr
					if err := b.runner.Run(cmdPush); err != nil {
						return fmt.Errorf("failed to push image %s: %w", imageName, err)
					}
				}
			}
		}
	}
	return nil
}

// zipAndCopyPlugins zips the compiled .so files and copies them to the output directory.
func (b *Builder) zipAndCopyPlugins() error {
	pluginDir := filepath.Join(b.workspacePath, "plugins_out")
	zipFilePath := filepath.Join(b.outputPath, b.config.ZipFileName)

	files, err := os.ReadDir(pluginDir)
	if err != nil || len(files) == 0 {
		fmt.Println("No plugins were built, skipping zip and copy.")
		return nil
	}

	// Create zip archive
	fmt.Printf("Creating zip archive at %s...\n", zipFilePath)
	cmd := exec.Command("zip", "-r", zipFilePath, ".")
	cmd.Dir = pluginDir
	if err := b.runner.Run(cmd); err != nil {
		return fmt.Errorf("failed to create zip archive: %w", err)
	}

	fmt.Println("✅ Zip archive and plugins copied successfully.")
	return nil
}