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

SET BLD_SINGLE=msbuild-single
SET TARGET_DEFAULT=DEFAULT

SET TARGET=%~1
IF [%TARGET%]==[] (
  SET TARGET=%TARGET_DEFAULT%
)

GOTO :no_banner

ECHO.%BSC%
ECHO.Running script %SCR%%~n0%BSC%
ECHO.This will try to build all currently known configurations
ECHO.of the openssl-cng-engine project. If not all SDKs or
ECHO.VS versions are installed, this will emit errors.
ECHO.
ECHO.Note that this is mostly for testing purposes to see if
ECHO.everything builds fine. You probably do not want to use
ECHO.this for any other purposes.
ECHO.
ECHO.Usage:  %SCR%%~n0%BSC% [%VAL%Target%BSC%]
ECHO.The value of %VAL%Target%BSC%, if present, is forwarded
ECHO.to the script %SCR%%BLD_SINGLE%%BSC%. If not present, it
ECHO.will be replaced with the value %VAL%%TARGET_DEFAULT%%BSC%.
ECHO.
ECHO.Value being forwarded is currently: %VAL%%TARGET%
ECHO.%NRM%


:no_banner
SET SCRIPT_DIR=%~dp0
FOR %%V IN (VS2019,VS2017) DO (
  FOR %%S IN (2004,1903,1809) DO (
    REM ECHO.%SCR%%~n0%ACT%: MSBuilding for target %VAL%%TARGET%%ACT% with %VAL%%%V%ACT% using SDK version %VAL%%%S%NRM% 
    CALL %SCRIPT_DIR%%BLD_SINGLE%.bat %TARGET% %%S %%V
  )
)


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
