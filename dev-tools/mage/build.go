// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package mage

import (
	"errors"
	"fmt"
	"go/build"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/josephspurrier/goversioninfo"
	"github.com/magefile/mage/sh"
)

// BuildArgs are the arguments used for the "build" target and they define how
// "go build" is invoked.
type BuildArgs struct {
	Name        string // Name of binary. (On Windows '.exe' is appended.)
	InputFiles  []string
	OutputDir   string
	CGO         bool
	BuildMode   string // Controls `go build -buildmode`
	Static      bool
	Env         map[string]string
	LDFlags     []string
	Vars        map[string]string // Vars that are passed as -X key=value with the ldflags.
	ExtraFlags  []string
	WinMetadata bool // Add resource metadata to Windows binaries (like add the version number to the .exe properties).
}

// buildTagRE is a regexp to match strings like "-tags=abcd"
// but does not match "-tags= "
var buildTagRE = regexp.MustCompile(`-tags=([\S]+)?`)

// ParseBuildTags returns the ExtraFlags param where all flags that are go build tags are joined by a comma.
//
// For example if given -someflag=val1 -tags=buildtag1 -tags=buildtag2
// It will return -someflag=val1 -tags=buildtag1,buildtag2
func (b BuildArgs) ParseBuildTags() []string {
	flags := make([]string, 0)
	if len(b.ExtraFlags) == 0 {
		return flags
	}

	buildTags := make([]string, 0)
	for _, flag := range b.ExtraFlags {
		if buildTagRE.MatchString(flag) {
			arr := buildTagRE.FindStringSubmatch(flag)
			if len(arr) != 2 || arr[1] == "" {
				log.Printf("Parsing buildargs.ExtraFlags found strange flag %q ignoring value", flag)
				continue
			}
			buildTags = append(buildTags, arr[1])
		} else {
			flags = append(flags, flag)
		}
	}
	if len(buildTags) > 0 {
		flags = append(flags, "-tags="+strings.Join(buildTags, ","))
	}
	return flags
}

// DefaultBuildArgs returns the default BuildArgs for use in builds.
func DefaultBuildArgs() BuildArgs {
	args := BuildArgs{
		Name: BeatName,
		CGO:  build.Default.CgoEnabled,
		Env:  map[string]string{},
		Vars: map[string]string{
			elasticBeatsModulePath + "/libbeat/version.buildTime": "{{ date }}",
			elasticBeatsModulePath + "/libbeat/version.commit":    "{{ commit }}",
		},
		WinMetadata: true,
	}
	if versionQualified {
		args.Vars[elasticBeatsModulePath+"/libbeat/version.qualifier"] = "{{ .Qualifier }}"
	}

	if positionIndependentCodeSupported() {
		args.BuildMode = "pie"
	}

	if DevBuild {
		// Disable optimizations (-N) and inlining (-l) for debugging.
		args.ExtraFlags = append(args.ExtraFlags, `-gcflags=all=-N -l`)
	} else {
		// Strip all debug symbols from binary (does not affect Go stack traces).
		args.LDFlags = append(args.LDFlags, "-s")
		// Remove all file system paths from the compiled executable, to improve build reproducibility
		args.ExtraFlags = append(args.ExtraFlags, "-trimpath")
	}
	if FIPSBuild {
		for _, tag := range FIPSConfig.Compile.Tags {
			args.ExtraFlags = append(args.ExtraFlags, "-tags="+tag)
		}
		args.CGO = args.CGO || FIPSConfig.Compile.CGO
		for varName, value := range FIPSConfig.Compile.Env {
			args.Env[varName] = value
		}
	}

	return args
}

// positionIndependentCodeSupported checks if the target platform support position independent code (or ASLR).
//
// The list of supported platforms is compiled based on the Go release notes: https://golang.org/doc/devel/release.html
// The list has been updated according to the Go version: 1.16
func positionIndependentCodeSupported() bool {
	return oneOf(Platform.GOOS, "darwin") ||
		(Platform.GOOS == "linux" && oneOf(Platform.GOARCH, "riscv64", "amd64", "arm", "arm64", "ppc64le", "386")) ||
		(Platform.GOOS == "aix" && Platform.GOARCH == "ppc64") ||

		// Windows 32bit supports ASLR, but Windows Server 2003 and earlier do not.
		// According to the support matrix (https://www.elastic.co/support/matrix), these old versions
		// are not supported.
		(Platform.GOOS == "windows")
}

func oneOf(value string, lst ...string) bool {
	for _, other := range lst {
		if other == value {
			return true
		}
	}
	return false
}

// DefaultGolangCrossBuildArgs returns the default BuildArgs for use in
// cross-builds.
func DefaultGolangCrossBuildArgs() BuildArgs {
	args := DefaultBuildArgs()
	args.Name += "-" + Platform.GOOS + "-" + Platform.Arch
	args.OutputDir = filepath.Join("build", "golang-crossbuild")
	if bp, found := BuildPlatforms.Get(Platform.Name); found {
		args.CGO = bp.Flags.SupportsCGO()
	}

	// Enable DEP (data execution protection) for Windows binaries.
	if Platform.GOOS == "windows" {
		args.LDFlags = append(args.LDFlags, "-extldflags=-Wl,--nxcompat")
	}

	return args
}

// GolangCrossBuild invokes "go build" inside of the golang-crossbuild Docker
// environment.
func GolangCrossBuild(params BuildArgs) error {
	if os.Getenv("GOLANG_CROSSBUILD") != "1" {
		return errors.New("Use the crossBuild target. golangCrossBuild can " +
			"only be executed within the golang-crossbuild docker environment.")
	}

	defer DockerChown(filepath.Join(params.OutputDir, params.Name+binaryExtension(GOOS)))
	defer DockerChown(filepath.Join(params.OutputDir))

	mountPoint, err := ElasticBeatsDir()
	if err != nil {
		return err
	}
	if err := sh.Run("git", "config", "--global", "--add", "safe.directory", mountPoint); err != nil {
		return err
	}

	// Support projects outside of the beats directory.
	repoInfo, err := GetProjectRepoInfo()
	if err != nil {
		return err
	}

	// TODO: Support custom build dir/subdir
	projectMountPoint := filepath.ToSlash(filepath.Join("/go", "src", repoInfo.CanonicalRootImportPath))
	if err := sh.Run("git", "config", "--global", "--add", "safe.directory", projectMountPoint); err != nil {
		return err
	}

	return Build(params)
}

func BuildOTel() error {
	args := DefaultBuildArgs()
	args.ExtraFlags = append(args.ExtraFlags, "-tags", "otelbeat")
	return Build(args)
}

// Build invokes "go build" to produce a binary.
func Build(params BuildArgs) error {
	fmt.Println(">> build: Building", params.Name)

	binaryName := params.Name + binaryExtension(GOOS)

	if params.OutputDir != "" {
		if err := os.MkdirAll(params.OutputDir, 0755); err != nil {
			return err
		}
	}

	// Environment
	env := params.Env
	if env == nil {
		env = map[string]string{}
	}
	cgoEnabled := "0"
	if params.CGO {
		cgoEnabled = "1"
	}
	env["CGO_ENABLED"] = cgoEnabled

	// Spec
	args := []string{
		"build",
		"-o",
		filepath.Join(params.OutputDir, binaryName),
	}
	if params.BuildMode != "" {
		args = append(args, "-buildmode", params.BuildMode)
	}
	args = append(args, params.ParseBuildTags()...)

	// ldflags
	ldflags := params.LDFlags
	if params.Static {
		ldflags = append(ldflags, `-extldflags '-static'`)
	}
	for k, v := range params.Vars {
		ldflags = append(ldflags, fmt.Sprintf("-X %v=%v", k, v))
	}
	if len(ldflags) > 0 {
		args = append(args, "-ldflags")
		args = append(args, MustExpand(strings.Join(ldflags, " ")))
	}

	if len(params.InputFiles) > 0 {
		args = append(args, params.InputFiles...)
	}

	if GOOS == "windows" && params.WinMetadata {
		log.Println("Generating a .syso containing Windows file metadata.")
		syso, err := MakeWindowsSysoFile()
		if err != nil {
			return fmt.Errorf("failed generating Windows .syso metadata file: %w", err)
		}
		defer os.Remove(syso)
	}

	log.Println("Adding build environment vars:", env)
	return sh.RunWith(env, "go", args...)
}

// MakeWindowsSysoFile generates a .syso file containing metadata about the
// executable file like vendor, version, copyright. The linker automatically
// discovers the .syso file and incorporates it into the Windows exe. This
// allows users to view metadata about the exe in the Details tab of the file
// properties viewer.
func MakeWindowsSysoFile() (string, error) {
	version, err := BeatQualifiedVersion()
	if err != nil {
		return "", err
	}

	commit, err := CommitHash()
	if err != nil {
		return "", err
	}

	major, minor, patch, err := ParseVersion(version)
	if err != nil {
		return "", err
	}
	fileVersion := goversioninfo.FileVersion{Major: major, Minor: minor, Patch: patch}

	vi := &goversioninfo.VersionInfo{
		FixedFileInfo: goversioninfo.FixedFileInfo{
			FileVersion:    fileVersion,
			ProductVersion: fileVersion,
			FileType:       "01", // Application
		},
		StringFileInfo: goversioninfo.StringFileInfo{
			CompanyName:      BeatVendor,
			ProductName:      strings.Title(BeatName),
			ProductVersion:   version,
			FileVersion:      version,
			FileDescription:  BeatDescription,
			OriginalFilename: BeatName + ".exe",
			LegalCopyright:   "Copyright " + BeatVendor + ", License " + BeatLicense,
			Comments:         "commit=" + commit,
		},
	}

	vi.Build()
	vi.Walk()
	sysoFile := BeatName + "_windows_" + GOARCH + ".syso"
	if err = vi.WriteSyso(sysoFile, GOARCH); err != nil {
		return "", fmt.Errorf("failed to generate syso file with Windows metadata: %w", err)
	}
	return sysoFile, nil
}
