################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
S_SRCS += \
C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Drivers/CMSIS/Device/ST/STM32F4xx/Source/Templates/gcc/startup_stm32f429xx.s 

OBJS += \
./Application/SW4STM32/startup_stm32f429xx.o 


# Each subdirectory must supply rules for building sources it contributes
Application/SW4STM32/startup_stm32f429xx.o: C:/Users/Pascal/Dropbox/SEcube\ code/Device/Eclipse/Drivers/CMSIS/Device/ST/STM32F4xx/Source/Templates/gcc/startup_stm32f429xx.s
	@echo 'Building file: $<'
	@echo 'Invoking: MCU GCC Assembler'
	@echo %cd%
	arm-none-eabi-as -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -g -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


