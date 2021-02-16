################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Src/usbd_core.c \
C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Src/usbd_ctlreq.c \
C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Src/usbd_ioreq.c \
C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Src/usbd_msc.c \
C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Src/usbd_msc_bot.c \
C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Src/usbd_msc_data.c \
C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Src/usbd_msc_scsi.c 

OBJS += \
./Middlewares/USB_Device_Library/usbd_core.o \
./Middlewares/USB_Device_Library/usbd_ctlreq.o \
./Middlewares/USB_Device_Library/usbd_ioreq.o \
./Middlewares/USB_Device_Library/usbd_msc.o \
./Middlewares/USB_Device_Library/usbd_msc_bot.o \
./Middlewares/USB_Device_Library/usbd_msc_data.o \
./Middlewares/USB_Device_Library/usbd_msc_scsi.o 

C_DEPS += \
./Middlewares/USB_Device_Library/usbd_core.d \
./Middlewares/USB_Device_Library/usbd_ctlreq.d \
./Middlewares/USB_Device_Library/usbd_ioreq.d \
./Middlewares/USB_Device_Library/usbd_msc.d \
./Middlewares/USB_Device_Library/usbd_msc_bot.d \
./Middlewares/USB_Device_Library/usbd_msc_data.d \
./Middlewares/USB_Device_Library/usbd_msc_scsi.d 


# Each subdirectory must supply rules for building sources it contributes
Middlewares/USB_Device_Library/usbd_core.o: C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Src/usbd_core.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU GCC Compiler'
	@echo %cd%
	arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -D__weak="__attribute__((weak))" -D__packed="__attribute__((__packed__))" -DUSE_HAL_DRIVER -DSTM32F429xx -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc/Legacy" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Include" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Device/ST/STM32F4xx/Include"  -O0 -g3 -Wall -fmessage-length=0 -ffunction-sections -c -fmessage-length=0 -MMD -MP -MF"Middlewares/USB_Device_Library/usbd_core.d" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

Middlewares/USB_Device_Library/usbd_ctlreq.o: C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Src/usbd_ctlreq.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU GCC Compiler'
	@echo %cd%
	arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -D__weak="__attribute__((weak))" -D__packed="__attribute__((__packed__))" -DUSE_HAL_DRIVER -DSTM32F429xx -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc/Legacy" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Include" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Device/ST/STM32F4xx/Include"  -O0 -g3 -Wall -fmessage-length=0 -ffunction-sections -c -fmessage-length=0 -MMD -MP -MF"Middlewares/USB_Device_Library/usbd_ctlreq.d" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

Middlewares/USB_Device_Library/usbd_ioreq.o: C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Src/usbd_ioreq.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU GCC Compiler'
	@echo %cd%
	arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -D__weak="__attribute__((weak))" -D__packed="__attribute__((__packed__))" -DUSE_HAL_DRIVER -DSTM32F429xx -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc/Legacy" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Include" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Device/ST/STM32F4xx/Include"  -O0 -g3 -Wall -fmessage-length=0 -ffunction-sections -c -fmessage-length=0 -MMD -MP -MF"Middlewares/USB_Device_Library/usbd_ioreq.d" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

Middlewares/USB_Device_Library/usbd_msc.o: C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Src/usbd_msc.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU GCC Compiler'
	@echo %cd%
	arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -D__weak="__attribute__((weak))" -D__packed="__attribute__((__packed__))" -DUSE_HAL_DRIVER -DSTM32F429xx -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc/Legacy" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Include" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Device/ST/STM32F4xx/Include"  -O0 -g3 -Wall -fmessage-length=0 -ffunction-sections -c -fmessage-length=0 -MMD -MP -MF"Middlewares/USB_Device_Library/usbd_msc.d" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

Middlewares/USB_Device_Library/usbd_msc_bot.o: C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Src/usbd_msc_bot.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU GCC Compiler'
	@echo %cd%
	arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -D__weak="__attribute__((weak))" -D__packed="__attribute__((__packed__))" -DUSE_HAL_DRIVER -DSTM32F429xx -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc/Legacy" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Include" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Device/ST/STM32F4xx/Include"  -O0 -g3 -Wall -fmessage-length=0 -ffunction-sections -c -fmessage-length=0 -MMD -MP -MF"Middlewares/USB_Device_Library/usbd_msc_bot.d" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

Middlewares/USB_Device_Library/usbd_msc_data.o: C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Src/usbd_msc_data.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU GCC Compiler'
	@echo %cd%
	arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -D__weak="__attribute__((weak))" -D__packed="__attribute__((__packed__))" -DUSE_HAL_DRIVER -DSTM32F429xx -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc/Legacy" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Include" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Device/ST/STM32F4xx/Include"  -O0 -g3 -Wall -fmessage-length=0 -ffunction-sections -c -fmessage-length=0 -MMD -MP -MF"Middlewares/USB_Device_Library/usbd_msc_data.d" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

Middlewares/USB_Device_Library/usbd_msc_scsi.o: C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Src/usbd_msc_scsi.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU GCC Compiler'
	@echo %cd%
	arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -D__weak="__attribute__((weak))" -D__packed="__attribute__((__packed__))" -DUSE_HAL_DRIVER -DSTM32F429xx -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/STM32F4xx_HAL_Driver/Inc/Legacy" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Core/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Middlewares/ST/STM32_USB_Device_Library/Class/MSC/Inc" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Include" -I"C:/Users/Pascal/Dropbox/SEcube code/Device/Eclipse/Drivers/CMSIS/Device/ST/STM32F4xx/Include"  -O0 -g3 -Wall -fmessage-length=0 -ffunction-sections -c -fmessage-length=0 -MMD -MP -MF"Middlewares/USB_Device_Library/usbd_msc_scsi.d" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


