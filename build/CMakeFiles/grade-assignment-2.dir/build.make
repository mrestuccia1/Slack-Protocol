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

# Utility rule file for grade-assignment-2.

# Include any custom commands dependencies for this target.
include CMakeFiles/grade-assignment-2.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/grade-assignment-2.dir/progress.make

CMakeFiles/grade-assignment-2:
	../tests/grade.py ../tests/rubrics/assignment-2.json

grade-assignment-2: CMakeFiles/grade-assignment-2
grade-assignment-2: CMakeFiles/grade-assignment-2.dir/build.make
.PHONY : grade-assignment-2

# Rule to build all files generated by this target.
CMakeFiles/grade-assignment-2.dir/build: grade-assignment-2
.PHONY : CMakeFiles/grade-assignment-2.dir/build

CMakeFiles/grade-assignment-2.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/grade-assignment-2.dir/cmake_clean.cmake
.PHONY : CMakeFiles/grade-assignment-2.dir/clean

CMakeFiles/grade-assignment-2.dir/depend:
	cd /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard/build /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard/build /Users/mrestuccia/Documents/uchicago/networks/chirc-mrestuccia-vaughnrichard/build/CMakeFiles/grade-assignment-2.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/grade-assignment-2.dir/depend

