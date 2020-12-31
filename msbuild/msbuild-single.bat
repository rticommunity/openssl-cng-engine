@ECHO OFF

:: (c) 2020 Copyright, Real-Time Innovations, Inc. (RTI)
::
::  Licensed under the Apache License, Version 2.0 (the "License");
::  you may not use this file except in compliance with the License.
::  You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
::  Unless required by applicable law or agreed to in writing, software
::  distributed under the License is distributed on an "AS IS" BASIS,
::  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
::  See the License for the specific language governing permissions and
::  limitations under the License.

SETLOCAL

CALL :set_colors

SET TARGET_DEFAULT=DEFAULT
SET SDK_DEFAULT=DEFAULT
SET VS_DEFAULT=DEFAULT

IF /I "%~1"=="Help" (
  CALL :usage
  GOTO done
)

ECHO.%BSC%
ECHO.Running script %SCR%%~n0%BSC% invoked with:
ECHO.  target = %VAL%%1%BSC%
ECHO.  sdk_version = %VAL%%2%BSC%
ECHO.  vs_version = %VAL%%3%BSC%%NRM%

SET SCRIPT_DIR=%~dp0
SET BSCE_DIR=%SCRIPT_DIR%\..
PUSHD "%BSCE_DIR%"

SET VS_WHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe
IF NOT EXIST "%VS_WHERE%" (
  SET "VS_WHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
)
IF EXIST "%VS_WHERE%" (
  GOTO vs_where_found
)

ECHO.%FLR%
ECHO.vswhere.exe is required, unable to figure out its location.%NRM%
GOTO failure


:vs_where_found
SET TARGET=%~1
IF [%TARGET%]==[] (
  SET TARGET=%TARGET_DEFAULT%
  GOTO target_found
)
IF /I "%TARGET%"=="%TARGET_DEFAULT%" (
  SET TARGET=%TARGET_DEFAULT%
  GOTO target_found
)
IF /I "%TARGET%"=="Build" (
  SET TARGET=Build
  GOTO target_found
)
IF /I "%TARGET%"=="Rebuild" (
  SET TARGET=Rebuild
  GOTO target_found
)
IF /I "%TARGET%"=="Clean" (
  SET TARGET=Clean
  GOTO target_found
)
IF /I "%TARGET%"=="Compile" (
  SET TARGET=Compile
  GOTO target_found
)

ECHO.%FLR%
ECHO.Target type %VAL%%TARGET%%FLR% not recognized%NRM%
CALL :usage
GOTO failure


:target_found
SET SDK_L1_N=2004
SET SDK_L1_D=10.0.19041.0
SET SDK_L1_S=VB
SET SDK_L2_N=1903
SET SDK_L2_D=10.0.18362.0
SET SDK_L2_S=19H1
SET SDK_L3_N=1809
SET SDK_L3_D=10.0.17763.0
SET SDK_L3_S=RS5

SET SDK=%~2
SET SDK_DEFAULT=DEFAULT
IF [%SDK%]==[]              SET SDK_VER=%SDK_DEFAULT%
IF "%SDK%"=="%SDK_DEFAULT%" SET SDK_VER=%SDK_DEFAULT%
IF "%SDK%"=="%SDK_L1_N%"    SET SDK_VER=%SDK_L1_D%
IF "%SDK%"=="%SDK_L1_D%"    SET SDK_VER=%SDK_L1_D%
IF "%SDK%"=="%SDK_L1_S%"    SET SDK_VER=%SDK_L1_D%
IF "%SDK%"=="%SDK_L2_N%"    SET SDK_VER=%SDK_L2_D%
IF "%SDK%"=="%SDK_L2_D%"    SET SDK_VER=%SDK_L2_D%
IF "%SDK%"=="%SDK_L2_S%"    SET SDK_VER=%SDK_L2_D%
IF "%SDK%"=="%SDK_L3_N%"    SET SDK_VER=%SDK_L3_D%
IF "%SDK%"=="%SDK_L3_D%"    SET SDK_VER=%SDK_L3_D%
IF "%SDK%"=="%SDK_L3_S%"    SET SDK_VER=%SDK_L3_D%

IF [%SDK_VER%]==[] (
  ECHO.%FLR%
  ECHO.SDK %VAL%%SDK%%FLR% not recognized%NRM%
  CALL :usage
  GOTO failure
) ELSE (
  IF "%SDK_VER%"=="%SDK_DEFAULT%" (
    SET SDK_INFO=latest installed
  ) ELSE (
    IF "%SDK%"=="%SDK_VER%" (
      SET SDK_INFO=%SDK%
	) ELSE (
      SET SDK_INFO=%SDK% ^(%SDK_VER%^)
	)
    IF "%SDK_VER%"=="%SDK_L1_D%" SET SDK_SUF=-%SDK_L1_N%
    IF "%SDK_VER%"=="%SDK_L2_D%" SET SDK_SUF=-%SDK_L2_N%
    IF "%SDK_VER%"=="%SDK_L3_D%" SET SDK_SUF=-%SDK_L3_N%
  )
)
SET VS_SOLUTION=openssl-cng-engine%SDK_SUF%.sln

IF "%TARGET%"=="%TARGET_DEFAULT%" (
  SET MSB_TARGET=
) ELSE (
  SET MSB_TARGET=-target:%TARGET%
)

SET VS_VERSION=%~3
IF [%VS_VERSION%]==[] (
  SET VS_VERSION=%VS_DEFAULT%
)
IF "%VS_VERSION%"=="%VS_DEFAULT%" (
  SET VS_LO=15
  SET VS_HI=17
  GOTO vs_version_found
)
IF /I "%VS_VERSION%"=="VS2019" (
  SET VS_LO=16
  SET VS_HI=17
  SET TOOLSET_VERSION=v142
  GOTO vs_version_found
)
IF /I "%VS_VERSION%"=="VS2017" (
  SET VS_LO=15
  SET VS_HI=16
  SET TOOLSET_VERSION=v141
  GOTO vs_version_found
)

ECHO.%FLR%
ECHO.Visual Studio version %VAL%%VS_VERSION%%FLR% not recognized
CALL :usage 
GOTO failure


:vs_version_found
REM Find the MsBuild initialization script
FOR /F "usebackq delims=" %%I IN (`"%VS_WHERE%" -property installationPath -version [%VS_LO%^,%VS_HI%^)`) DO (
  IF EXIST %%I\Common7\Tools\VsDevCmd.bat (
    SET VS_DEVCMD=%%I\Common7\Tools\VsDevCmd.bat
	GOTO msbuild_found
  )
)

IF [%VS_DEVCMD%]==[] (
  ECHO.%FLR%
  ECHO.Can not figure out where %VAL%%VS_VERSION%%FLR% development environment is located%NRM%
  CALL :usage
  GOTO failure
)

:msbuild_found

ECHO.%VS_DEVCMD% | FINDSTR /C:"2019">nul && (
  SET VS_VERSION_USED=VS2019
  SET TOOLSET_VERSION=v142
  SET CLANGF_CMD=clang-format
  SET CLANGF_DRYRUN_OPTIONS=--dry-run --Werror
) || ECHO.%VS_DEVCMD% | FINDSTR /C:"2017">nul && (
  SET VS_VERSION_USED=VS2017
  SET TOOLSET_VERSION=v141
  SET NUGET_CMD=nuget
) || (
  ECHO.%FLR%Warning: not sure which toolversion is being used%NRM%
  (CALL )
)

SET VS_INFO=%VS_VERSION_USED% (%TOOLSET_VERSION%)

SET LOG_DIR=log
IF NOT EXIST "%LOG_DIR%" MD "%LOG_DIR%"
SET BLD_SUF=-%TOOLSET_VERSION%%SDK_SUF%

ECHO.%BSC%
ECHO.MSBuild target : %VAL%%MSB_TARGET%%BSC%
ECHO.SDK info       : %VAL%%SDK_INFO%%BSC%
ECHO.VS version     : %VAL%%VS_INFO%%BSC%
ECHO.VS solution    : %VS_SOLUTION%
ECHO.Log files      : %LOG_DIR%^\^<CPU^>-^<Config^>%BLD_SUF%-^<Level^>.log
ECHO.Build dir      : bld^\^<CPU^>-^<Config^>%BLD_SUF%
ECHO.%NRM%

CALL "%VS_DEVCMD%"

ECHO.%ACT%
:: Newer versions of clang-format can conveniently check for formatting violations
:: For older versions, do not bother even trying some clumsy workaround :-)
IF DEFINED CLANGF_CMD (
  WHERE %CLANGF_CMD% 2>nul >nul && (
    ECHO.Verifying code formatting
    %CLANGF_CMD% %CLANGF_DRYRUN_OPTIONS% src\*.c src\*.h || GOTO :failure
  ) || (
    ECHO.%FLR%Warning: not verifying code formatting -- can not execute %CLANGF_CMD%%ACT%
	(CALL )
  )
) ELSE (
  ECHO.%FLR%Warning: not verifying code formatting -- need clang-format v10+%ACT%
)

:: Older versions of MSBuild do not support the convenient nuget restore options
:: In that case, try to execute the nuget command
IF DEFINED NUGET_CMD (
  WHERE %NUGET_CMD% 2>nul >nul && (
    ECHO.Restoring packages using nuget, if needed
    %NUGET_CMD% restore -PackagesDirectory packages -Verbosity quiet msbuild\packages.config
  ) || (
    ECHO.%FLR%Warning: can not execute %NUGET_CMD% -- build may fail%ACT%
	(CALL )
  )
)

FOR %%C IN (Debug,Release) DO (
  FOR %%P IN (x86,x64) DO (
    ECHO.MSBuild-ing %%P^|%%C	into bld^\%%P-%%C%BLD_SUF%
    MSBuild.exe                            ^
	  %VS_SOLUTION%                        ^
	  %MSB_TARGET%                         ^
	  -restore                             ^
	  -property:Platform=%%P               ^
	  -property:Configuration=%%C          ^
	  -property:RestorePackagesConfig=true ^
	  -verbosity:quiet                     ^
	  -nologo                              ^
	  -fl1 -flp1:logfile=%LOG_DIR%\%%P-%%C%BLD_SUF%-errors.log;errorsonly       ^
	  -fl2 -flp2:logfile=%LOG_DIR%\%%P-%%C%BLD_SUF%-warnings.log;warningsonly   ^
	  -fl3 -flp3:logfile=%LOG_DIR%\%%P-%%C%BLD_SUF%-normal.log;verbosity=normal ^
	  || GOTO :failure
  )
)
ECHO.%NRM%

:: Note to self: the following can be added to the MSBuild command for detailed logging:
:: -fl4 -flp4:logfile=%LOG_DIR%\%%P-%%C%BLD_SUF%-detailed.log;verbosity=detailed

:done
ECHO.Done
POPD
ENDLOCAL
GOTO :eof


:set_colors
FOR /F "tokens=1,2 delims=#" %%a IN ('"PROMPT #$H#$E# & ECHO on & FOR %%b IN (1) DO REM"') DO (
  SET ESC=%%b
  GOTO :set_codes
)

:set_codes
SET RED=%ESC%[31m
SET GRN=%ESC%[32m
SET YEL=%ESC%[33m
SET CYN=%ESC%[36m
SET WHT=%ESC%[37m
SET NRM=%ESC%[0m
REM Color codes
REM Basic text
SET BSC=%WHT%
REM Actions
SET ACT=%GRN%
REM Symbolic values
SET VAL=%CYN%
REM Script names
SET SCR=%YEL%
REM Failures
SET FLR=%RED%
GOTO :eof


:usage
ECHO.%BSC%
ECHO.  This is %SCR%%~n0%BSC%
ECHO.  A convenience script for building the CNG Engine plugins.
ECHO.
ECHO.  Usage: %SCR%%~n0%BSC% [[%VAL%target%BSC% [%VAL%sdk_name%BSC% [%VAL%vs_version%BSC%]]]
ECHO.
ECHO.    %VAL%target%BSC%
ECHO.      Optional MSBuild target to build for.
ECHO.      Recognized values are:
ECHO.        %VAL%
ECHO.        Clean
ECHO.        Compile
ECHO.        Build
ECHO.        Rebuild
ECHO.        %TARGET_DEFAULT%%BSC% will build the default target
ECHO.
ECHO.    %VAL%sdk_name%BSC%
ECHO.      Optional identifier of SDK version to build with.
ECHO.      SDK names are hard to remember and referenced to in
ECHO.      several ways by MicroSoft. The following values are
ECHO.      currently recognized and supported (with values in
ECHO.      the same column referring to the same SDK version)
ECHO.        %VAL%
ECHO.        10.0.19041.0  10.0.18362.0  10.0.17763.0 
ECHO.        2004          1903          1809
ECHO.        VB            19H1          RS5
ECHO.        %SDK_DEFAULT%%BSC% will use the latest installed SDK
ECHO.
ECHO.    %VAL%vs_version%BSC%
ECHO.      Optional Visual Studio toolchain version to use
ECHO.      Recognized values are:
ECHO.        %VAL%
ECHO.        VS2019
ECHO.        VS2017
ECHO.        %VS_DEFAULT%%BSC% will use the latest installed toolset
ECHO.
ECHO.     If settings are omitted, that is if less than three
ECHO.       arguments have been given, their default values will be
ECHO.       inserted.
ECHO.%NRM%
GOTO :eof


:failure
ECHO.%FLR%
ECHO.Failure detected, terminating now%NRM%
EXIT /B 1
