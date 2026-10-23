@echo off
rem Builds strata-gemma4-engine (engines\gemma4, Gemma 4 plans 2-3) into out\gemma4-engine with
rem MSVC v143 + CUDA 13.0 (sm_89), Ninja, Release. Usage: build-windows.bat [extra cmake -D args]
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
set "CUDA_ROOT=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.0"
set "OUT=C:\multi-strata\out\gemma4-engine"
cmake -G Ninja -S "C:\multi-strata\engines\gemma4" -B "%OUT%" ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_CUDA_ARCHITECTURES=89 ^
  "-DCMAKE_CUDA_COMPILER=%CUDA_ROOT%\bin\nvcc.exe" "-DCUDAToolkit_ROOT=%CUDA_ROOT%" ^
  "-DG4_MODEL_FILE=C:\Strata-data\models\gemma4_q8\gemma-4-26B-A4B-it-UD-Q8_K_XL.gguf" ^
  "-DG4_PYTHON=C:\multi-strata\.venv-dev\Scripts\python.exe" %* || exit /b 1
cmake --build "%OUT%" -j 12 || exit /b 1
