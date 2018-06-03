Кладём директорию с контрактом bcr в constracts

Редактируем файл CMakeModules/wasm.cmake для начитывания CMAKE_C_FLAGS
-    set(WASM_COMMAND ${WASM_CLANG} -emit-llvm -O3 ${STDFLAG} --target=wasm32 -ffreestanding
+    set(WASM_COMMAND ${WASM_CLANG} -emit-llvm -O3 ${STDFLAG} ${CMAKE_C_FLAGS} --target=wasm32 -ffreestanding

Добавляем в contracts/CMakeLists.txt строку
+add_subdirectory(bcr)

Выполняем make из сборочной директории
