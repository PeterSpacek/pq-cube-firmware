#include "se3_rand.h"
#include "rng.h"
#include "stm32f4xx_hal_rng.h"


bool se3_rand32(uint32_t *val){
	size_t i;
	HAL_StatusTypeDef ret;
	for(i=0; i<20; i++){
		ret=HAL_RNG_GenerateRandomNumber(&hrng, val);
		if(ret==HAL_OK){
			return true;
		}
		else if(ret==HAL_ERROR){
			return false;
		}
	}
	return false;
}

uint16_t se3_rand(uint16_t size, uint8_t* data){
	uint32_t tmp;
	size_t i,n;

	n=size/4;
	for(i=0;i<n;i++){
		if(!se3_rand32((uint32_t*)data)){
			return 0;
		}
		data+=4;
	}
	n=size%4;
	if(n!=0){
		if(!se3_rand32(&tmp)){
			return 0;
		}
		for(i=0;i<n;i++){
			data[i]=((uint8_t*)&tmp)[i];
		}
	}
	return size;
}
