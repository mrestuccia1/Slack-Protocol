# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.29

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/homebrew/Cellar/cmake/3.29.0/bin/cmake

# The command to remove a file.
RM = /opt/homebrew/Cellar/cmake/3.29.0/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard/build

# Utility rule file for tests-assignment-3.

# Include any custom commands dependencies for this target.
include CMakeFiles/tests-assignment-3.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/tests-assignment-3.dir/progress.make

CMakeFiles/tests-assignment-3: chirc
	pytest --chirc-rubric ../tests/rubrics/assignment-3.json ../tests/

tests-assignment-3: CMakeFiles/tests-assignment-3
tests-assignment-3: CMakeFiles/tests-assignment-3.dir/build.make
.PHONY : tests-assignment-3

# Rule to build all files generated by this target.
CMakeFiles/tests-assignment-3.dir/build: tests-assignment-3
.PHONY : CMakeFiles/tests-assignment-3.dir/build

CMakeFiles/tests-assignment-3.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/tests-assignment-3.dir/cmake_clean.cmake
.PHONY : CMakeFiles/tests-assignment-3.dir/clean

CMakeFiles/tests-assignment-3.dir/depend:
	cd /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard/build /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard/build /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard/build/CMakeFiles/tests-assignment-3.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/tests-assignment-3.dir/depend

