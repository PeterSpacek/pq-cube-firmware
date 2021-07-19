/**
  ******************************************************************************
  * File Name          : main.c
  * Description        : Main program body
  ******************************************************************************
  *
  * COPYRIGHT(c) 2016 STMicroelectronics
  *
  * Redistribution and use in source and binary forms, with or without modification,
  * are permitted provided that the following conditions are met:
  *   1. Redistributions of source code must retain the above copyright notice,
  *      this list of conditions and the following disclaimer.
  *   2. Redistributions in binary form must reproduce the above copyright notice,
  *      this list of conditions and the following disclaimer in the documentation
  *      and/or other materials provided with the distribution.
  *   3. Neither the name of STMicroelectronics nor the names of its contributors
  *      may be used to endorse or promote products derived from this software
  *      without specific prior written permission.
  *
  * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  ******************************************************************************
  */
/* Includes ------------------------------------------------------------------*/
#include "stm32f4xx_hal.h"
#include "adc.h"
#include "crc.h"
#include "dma.h"
#include "i2c.h"
#include "rng.h"
#include "sdio.h"
#include "spi.h"
#include "tim.h"
#include "usart.h"
#include "usb_device.h"
#include "gpio.h"
#include "fmc.h"

/* USER CODE BEGIN Includes */
#include "se3_core.h"

#include "se3_security_core.h"

/* USER CODE END Includes */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */
/* Private variables ---------------------------------------------------------*/

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);

uint32_t m_nStart;               //DEBUG Stopwatch start cycle counter value
uint32_t m_nStop;                //DEBUG Stopwatch stop cycle counter value
#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/kyber1024/kyber_api.h"
#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/kyber1024-m4/kyber_m4_api.h"
#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/kyber1024-m4-protected/kyber_m4_api_prot.h"

#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/ntruhps4096821/ntruhps4096821_api.h"
#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/ntruhps4096821-m4/ntruhps4096821_m4_api.h"

#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/firesaber/firesaber_api.h"
#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/saber-m4/saber_m4_api.h"


se3_kem_descriptor kems_table[SE3_KEM_ALGO_MAX] = {
		{ ///< CRYSTALS-KYBER
			KYBER1024_M4_crypto_kem_keypair_prot,
			KYBER1024_M4_crypto_kem_enc_prot,
			KYBER1024_M4_crypto_kem_dec_prot,
			KYBER1024_M4_CRYPTO_ALGNAME_prot,
			SE3_CRYPTO_TYPE_KEM,
			KYBER1024_M4_CRYPTO_BYTES_prot,
			KYBER1024_M4_CRYPTO_CIPHERTEXTBYTES_prot,
			KYBER1024_M4_CRYPTO_PUBLICKEYBYTES_prot,
			KYBER1024_M4_CRYPTO_SECRETKEYBYTES_prot
		},

		{ ///< CRYSTALS-KYBER
			PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair,
			PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc,
			PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec,
			PQCLEAN_KYBER1024_CLEAN_CRYPTO_ALGNAME,
			SE3_CRYPTO_TYPE_KEM,
			PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES,
			PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
			PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
			PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES
		},

		{ ///< CRYSTALS-KYBER
			KYBER1024_M4_crypto_kem_keypair,
			KYBER1024_M4_crypto_kem_enc,
			KYBER1024_M4_crypto_kem_dec,
			KYBER1024_M4_CRYPTO_ALGNAME,
			SE3_CRYPTO_TYPE_KEM,
			KYBER1024_M4_CRYPTO_BYTES,
			KYBER1024_M4_CRYPTO_CIPHERTEXTBYTES,
			KYBER1024_M4_CRYPTO_PUBLICKEYBYTES,
			KYBER1024_M4_CRYPTO_SECRETKEYBYTES
		},
		//{ NULL, NULL, NULL, "", 0, 0, 0, 0 },

		{ ///< NTRU
			PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_keypair,
			PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_enc,
			PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_dec,
			PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_ALGNAME,
			SE3_CRYPTO_TYPE_KEM,
			PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_BYTES,
			PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_CIPHERTEXTBYTES,
			PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_PUBLICKEYBYTES,
			PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_SECRETKEYBYTES
		},

		{ ///< NTRU
			NTRUHPS4096821_M4_crypto_kem_keypair,
			NTRUHPS4096821_M4_crypto_kem_enc,
			NTRUHPS4096821_M4_crypto_kem_dec,
			NTRUHPS4096821_M4_CRYPTO_ALGNAME,
			SE3_CRYPTO_TYPE_KEM,
			NTRUHPS4096821_M4_CRYPTO_BYTES,
			NTRUHPS4096821_M4_CRYPTO_CIPHERTEXTBYTES,
			NTRUHPS4096821_M4_CRYPTO_PUBLICKEYBYTES,
			NTRUHPS4096821_M4_CRYPTO_SECRETKEYBYTES
		},

		{ ///< FIRESABER
			PQCLEAN_FIRESABER_CLEAN_crypto_kem_keypair,
			PQCLEAN_FIRESABER_CLEAN_crypto_kem_enc,
			PQCLEAN_FIRESABER_CLEAN_crypto_kem_dec,
			PQCLEAN_FIRESABER_CLEAN_CRYPTO_ALGNAME,
			SE3_CRYPTO_TYPE_KEM,
			PQCLEAN_FIRESABER_CLEAN_CRYPTO_BYTES,
			PQCLEAN_FIRESABER_CLEAN_CRYPTO_CIPHERTEXTBYTES,
			PQCLEAN_FIRESABER_CLEAN_CRYPTO_PUBLICKEYBYTES,
			PQCLEAN_FIRESABER_CLEAN_CRYPTO_SECRETKEYBYTES
		},

		{ ///< FIRESABER
			SABER_M4_crypto_kem_keypair,
			SABER_M4_crypto_kem_enc,
			SABER_M4_crypto_kem_dec,
			SABER_M4_CRYPTO_ALGNAME,
			SE3_CRYPTO_TYPE_KEM,
			SABER_M4_CRYPTO_BYTES,
			SABER_M4_CRYPTO_CIPHERTEXTBYTES,
			SABER_M4_CRYPTO_PUBLICKEYBYTES,
			SABER_M4_CRYPTO_SECRETKEYBYTES
		},
		{ NULL, NULL, NULL, "", 0, 0, 0, 0 }


	};



/* USER CODE BEGIN PFP */
/* Private function prototypes -----------------------------------------------*/
uint16_t test_implementation();
uint16_t erease();
/* USER CODE END PFP */

/* USER CODE BEGIN 0 */
//#define TEST 1


static inline void stopwatch_reset(void)
{
    /* Enable DWT */
    DEMCR |= DEMCR_TRCENA;
    *DWT_CYCCNT = 0;
    /* Enable CPU cycle counter */
    DWT_CTRL |= CYCCNTENA;
}


/* USER CODE END 0 */


int main(void)
{

	/* USER CODE BEGIN 1 */
	// Init SEcube structures


	/* USER CODE END 1 */

	/* MCU Configuration----------------------------------------------------------*/

	/* Reset of all peripherals, Initializes the Flash interface and the Systick. */
	HAL_Init();

	/* Configure the system clock */
	SystemClock_Config();

	/* Initialize all configured peripherals */
	MX_GPIO_Init();
	MX_DMA_Init();
	MX_ADC1_Init();
	MX_FMC_Init();
	MX_I2C2_Init();
	MX_SDIO_SD_Init();
	MX_SPI5_Init();
	MX_TIM4_Init();
	MX_USART1_UART_Init();
	MX_USART6_SMARTCARD_Init();
	MX_USB_DEVICE_Init();
	MX_CRC_Init();
	MX_RNG_Init();

	/* USER CODE BEGIN */

	device_init();

	#ifdef TEST
		test_implementation();
	#else
		device_loop();
	#endif

	/* USER CODE END  */


	return 0;
}



// return the largest sizes for parameters in kems?
uint16_t max_sizes(uint32_t* max_ciphertext_size, uint32_t* max_public_key_size,uint32_t* max_secret_key_size,uint32_t* max_size)
{
	*max_ciphertext_size=0;
	*max_public_key_size=0;
	*max_secret_key_size=0;
	*max_size=0;
	uint32_t tmp;

	uint32_t status=1,var;
    for (var = 0; var < SE3_KEM_ALGO_MAX; var++) {
    	tmp=kems_table[var].display_ciphertext_size;
    	if(tmp>*max_ciphertext_size)
    		*max_ciphertext_size=tmp;
    	tmp=kems_table[var].display_public_key_size;
    	if(tmp>*max_public_key_size)
    		*max_public_key_size=tmp;
    	tmp=kems_table[var].display_secret_key_size;
    	if(tmp>*max_secret_key_size)
    		*max_secret_key_size=tmp;
    	tmp=kems_table[var].display_size;
    	if(tmp>*max_size)
    		*max_size=tmp;

	}
    return status;
}


uint16_t erease()
{
	se3_flash_it it = { .addr = NULL };
	se3_flash_it_init(&it);

    while (se3_flash_it_next(&it))
    	if (it.type !=1){
 		   se3_flash_it_delete(&it);
    		it.type=0xFF;

    	}

}

uint16_t test_implementation()
{

    uint32_t status,var;


    uint32_t max_ciphertext_size;
    uint32_t max_public_key_size;
    uint32_t max_secret_key_size;
    uint32_t max_size;
    max_sizes(&max_ciphertext_size,&max_public_key_size,&max_secret_key_size,&max_size);

    uint8_t* ciphertext= malloc(max_ciphertext_size);
    uint8_t* public_key= malloc(max_public_key_size);
    uint8_t* secret_key= malloc(max_secret_key_size);
    uint8_t* symmetric_key= malloc(max_size);
    uint8_t* symmetric_key2= malloc(max_size);


    uint64_t timer, a,b;
    uint64_t data[SE3_KEM_ALGO_MAX*3];


    for (var = 0; var < SE3_KEM_ALGO_MAX-1; var++) {


    	timer=0;
        for(int i =0;i<NUM_OF_TESTS;i++){
        	//SysTick->VAL = 0; // set 0
			stopwatch_reset();
			__disable_irq();
			STOPWATCH_START;
			//a = (uint32_t) SysTick->VAL;
			status = kems_table[var].keypair(public_key,secret_key);
	    	//__asm__(".rept 100 ; nop ; .endr");
			STOPWATCH_STOP;
			//b = (uint32_t) SysTick->VAL;
			__enable_irq();
			//timer += 0x00FFFFFF&(a - b);
			timer += m_nStop - m_nStart;
	        if (SE3_OK != status) {
	            free(ciphertext);
	            free(public_key);
	            free(secret_key);
	            free(symmetric_key);
	            free(symmetric_key2);
	            return status;
	        }
        }
        timer/=NUM_OF_TESTS;
/*
    	timer=0;
    	stopwatch_reset();
    	__disable_irq();
    	STOPWATCH_START;

    	__asm__(".rept 1000 ; nop ; .endr");
    	STOPWATCH_STOP;
    	//b = (uint32_t) SysTick->VAL;
    	__enable_irq();

    	//timer += 0x00FFFFFF&(a - b);
    	timer += m_nStop - m_nStart;
*/
        data[var*3+0]=timer;


    	timer=0;
        for(int i =0;i<NUM_OF_TESTS;i++){
        	//SysTick->VAL = 0; // set 0
			stopwatch_reset();
			__disable_irq();
			STOPWATCH_START;
			//a = (uint32_t) SysTick->VAL;
			status = kems_table[var].enc(ciphertext, symmetric_key, public_key);

	   /* 	for(int j=0; j<100;j++)
		    	__asm__("nop");*/
			STOPWATCH_STOP;
			//b = (uint32_t) SysTick->VAL;
			__enable_irq();
			//timer += 0x00FFFFFF&(a - b);
			timer += m_nStop - m_nStart;

	        if (SE3_OK != status) {
	            free(ciphertext);
	            free(public_key);
	            free(secret_key);
	            free(symmetric_key);
	            free(symmetric_key2);
	        }
		}
		timer/=NUM_OF_TESTS;
        data[var*3+1]=timer;


    	timer=0;
        for(int i =0;i<NUM_OF_TESTS;i++){
        	//SysTick->VAL = 0; // set 0
			stopwatch_reset();
			__disable_irq();
			//a = (uint32_t) SysTick->VAL;
			STOPWATCH_START;
			status = kems_table[var].dec(symmetric_key2, ciphertext, secret_key);
			/*
	    	for(int j=0; j<100;j+=5){
		    	__asm__("nop");
		    	__asm__("nop");
		    	__asm__("nop");
		    	__asm__("nop");
		    	__asm__("nop");
	    	}
	    	*/
			STOPWATCH_STOP;
			//b = (uint32_t) SysTick->VAL;
			__enable_irq();
			//timer += 0x00FFFFFF&(a - b);
			timer += m_nStop - m_nStart;

	        if (SE3_OK != status) {
	            free(ciphertext);
	            free(public_key);
	            free(secret_key);
	            free(symmetric_key);
	            free(symmetric_key2);
	            return status;
	        }
		}
		timer/=NUM_OF_TESTS;
        data[var*3+2]=timer;

    	/* Compare plain data with decrypted data */
    	if (memcmp(symmetric_key, symmetric_key2, kems_table[var].display_size)!= 0) {
            return SE3_ERR_STATE;
    	}
	}

    se3_flash_key dataStru;
    se3_flash_it it = { .addr = NULL };
    dataStru.data=(uint8_t *)data;


    dataStru.id = TEST_ID;
    dataStru.data_size=sizeof(data);
    dataStru.name = "this is not a key";
    dataStru.validity = 0;
    dataStru.name_size = strlen(dataStru.name);
    se3_flash_it_init(&it);
           if (!se3_key_find(dataStru.id, &it)) {
               it.addr = NULL;
           }
           else {
               return SE3_ERR_RESOURCE;
           }
           if (!se3_key_new(&it, &dataStru)) {
               SE3_TRACE(("[crypto_kem_keypair] pk se3_key_new failed\n"));
               return SE3_ERR_MEMORY;
           }

    free(ciphertext);
    free(public_key);
    free(secret_key);
    free(symmetric_key);
    free(symmetric_key2);

	return status;
}
/** System Clock Configuration
*/
void SystemClock_Config(void)
{

	RCC_OscInitTypeDef RCC_OscInitStruct;
	RCC_ClkInitTypeDef RCC_ClkInitStruct;

	__PWR_CLK_ENABLE();
	__HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

	RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
	RCC_OscInitStruct.HSEState = RCC_HSE_ON;
	RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
	RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;

	#ifdef TEST

	RCC_OscInitStruct.PLL.PLLM = 16;
	RCC_OscInitStruct.PLL.PLLN = 192;
	RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV8;
	RCC_OscInitStruct.PLL.PLLQ = 8;/*

	RCC_OscInitStruct.PLL.PLLM = 16;
	RCC_OscInitStruct.PLL.PLLN = 64;
	RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV8;
	RCC_OscInitStruct.PLL.PLLQ = 8;
	*/
	#else
	RCC_OscInitStruct.PLL.PLLM = 16;
	RCC_OscInitStruct.PLL.PLLN = 336;
	RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
	RCC_OscInitStruct.PLL.PLLQ = 7;
	#endif


	HAL_RCC_OscConfig(&RCC_OscInitStruct);

	#ifdef TEST

	RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
							  |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
	RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
	RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV2;
	RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
	RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
	HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0);
	#else
	RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
							  |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
	RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
	RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
	RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
	RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;
	HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5);
	#endif

	HAL_RCC_MCOConfig(RCC_MCO1, RCC_MCO1SOURCE_PLLCLK, RCC_MCODIV_2);

	HAL_SYSTICK_Config(HAL_RCC_GetHCLKFreq()/1000);

	HAL_SYSTICK_CLKSourceConfig(SYSTICK_CLKSOURCE_HCLK);

	/* SysTick_IRQn interrupt configuration */
	HAL_NVIC_SetPriority(SysTick_IRQn, 0, 0);

	FLASH->ACR &= ~FLASH_ACR_ICEN;
	/* disable flash data cache */
	FLASH->ACR &= ~FLASH_ACR_DCEN;
	/* enable prefetch buffer */
	FLASH->ACR |= FLASH_ACR_PRFTEN;
	__asm("wfi"); //wait for a systick interrupt, i.e. delay(1)
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

#ifdef USE_FULL_ASSERT

/**
   * @brief Reports the name of the source file and the source line number
   * where the assert_param error has occurred.
   * @param file: pointer to the source file name
   * @param line: assert_param error line source number
   * @retval None
   */
void assert_failed(uint8_t* file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
    ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */

}

#endif

/**
  * @}
  */ 

/**
  * @}
*/ 

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
