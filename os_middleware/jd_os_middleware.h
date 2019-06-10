

/*****************************************************************
 设计目的，头文件保持平台无关
 *****************************************************************/
#ifndef __JD_OS_MIDDLEWARE_H__
#define __JD_OS_MIDDLEWARE_H__

#define TLC_COMM  1

#include "typedef.h"

#if( TLC_COMM == 1 )
#include "stpllc.h"
#include "stptlc.h"
#endif



typedef void* JD_OM_QUEUE;
typedef void* JD_OM_SEM;
typedef void* JD_OM_MUTEX;
typedef int JD_OM_TIMER;
typedef void* JD_OM_THREAD;


#define JD_OS_PORT_NUM_E   int
#define JD_OS_BOARD_ADDR_E int
#define JDOM_PORT int
#define JDOM_ADDR TLC_ADDR

#if 1
enum{
	MQ_PEEK_EMPTY = -1,
	MQ_INVALUED   = -2,
	MQ_LOCK_ERROR = -3,
};
#define MQ_EMPTY MQ_PEEK_EMPTY

typedef enum  {
    osOK         =   0,
    osErrorOS    =   1,
}osStatus;
#else

//#include "api_file_manager.h"

#endif
typedef enum  {
	osOKa = 0,
}osPriority;

typedef struct tag_jd_om_comm {
#if( TLC_COMM == 1 )
	stptlc  * ptlc;
#endif
}jd_om_comm;

typedef struct tag_jd_om_comm_addr {
#if( TLC_COMM == 1 )
	tlc_addr addr;
#endif
}jd_om_comm_addr;



// typedef enum
// {
//     JD_OM_JZ_MASTER_CTRL_MODE        = 1,
//     JD_OM_JZ_SLAVE_CTRL_MODE         = 2,
//     JD_OM_JZ_INTERGRATED_MODE        = 3,

//     JD_OM_ZY_MASTER_CTRL_MODE        = 11,
//     JD_OM_ZY_SLAVE_CTRL_MODE         = 12,
//     JD_OM_ZY_INTERGRATED_MODE        = 13,

//     JD_OM_OTHER_MODE                 = 99,
// }JD_OS_MIDDLEWARE_MODE_E;

// /*****************************************************************
// * Function:     jd_om_set_mode
// *
// * Description:  设置中间件的运行模式.
// *
// * Parameters:
// *               mode: 见枚举定义JD_OS_MIDDLEWARE_MODE_E
// *
// * Return:       void
// *****************************************************************/
// int jd_om_set_mode(JD_OS_MIDDLEWARE_MODE_E mode);


/*****************************************************************
 * Function:     jd_om_comm_open
 *
 * Description:  初始化一个发送者.
 *
 * Parameters:
 *               jd_om_comm 指针
 *               port_num:端口，在底层可以用这个选择不同串口或者socket 端口
 *               local_addr: 本机地址    eg:android addr: “2.0.0”
 *               mask_addr: 本机地址掩码                  “255.0.0.”
 *               rate: 串口波特率
 * Return:
 *               0   : 成功
 *              other:失败
 *****************************************************************/
int jd_om_comm_open(
                    jd_om_comm * handle,
                    char * uart_name,
                    jd_om_comm_addr *local_addr,
                    jd_om_comm_addr *mask_addr,
                    int rate);

/*****************************************************************
 * Function:     jd_om_comm_close
 *
 * Description:  关闭发送者.
 *
 * Parameters:
 *               jd_om_comm 指针
 * Return:
 *               0   : 成功
 *              other:失败
 *****************************************************************/
int jd_om_comm_close(jd_om_comm * handle);

/*****************************************************************
* Function:     jd_om_send
*
* Description:  发送消息.
*
* Parameters:
*               jd_om_comm 指针
*               toaddr: 目的地址
*               board_addr: 接收数据的目的地址
*               data: 待发送的数据
*               data_len：数据长度
*               msec: -1:不可靠传输  0:可靠传输
*
* Return:
*               实际发送的数据长度
*
*****************************************************************/
int jd_om_send(	jd_om_comm * handle,
				jd_om_comm_addr * toaddr,
				void * data,
				int data_len,
				int msec);


#define IN
#define OUT
/*****************************************************************
* Function:     jd_om_recv
*
* Description:  板接收消息.
*
* Parameters:
*               jd_om_comm 指针
*               fromaddr：远程发生者源地址
*               data: 数据
*               data_len: 数据长度
*
* Return:
*               -1: 接收失败
*               other: 实际接收数据的长度
*****************************************************************/
int jd_om_recv(
		jd_om_comm * handle,
		OUT jd_om_comm_addr *fromaddr,
		void * data,
		int data_len);
/*****************************************************************
* Function:     jd_om_send_2_batt
*
* Description:  发送数据到BATT Board
*
* Parameters:
*               jd_om_comm 指针
*               batt_id：电池槽id（1 - 12）
*               data：待发送的数据
*               data_len：数据长度
*
* Return:
*               实际发送的数据长度
*
*****************************************************************/
int jd_om_send_2_batt(jd_om_comm * handle,
                      void * data,
                      int data_len);

/*****************************************************************
* Function:     jd_om_recv_f_batt
*
* Description:  接收电池数据
*
* Parameters:
*               jd_om_comm 指针
*               batt_id：电池槽id（1 - 12）
*               data：接收到的数据
*               data_len：数据长度
*
* Return:
*               -1：接收失败
*               other:实际接收的数据长度
*
*****************************************************************/
int jd_om_recv_f_batt(jd_om_comm * handle,
                      void * data,
                      int data_len);


/*********************** Thread Management *****************************
 *    jd_om_thread_create() //主要是这个函数的参数
 *    osStatus jd_threaddelete(osThreadId thread_id);
 *    osThreadId jd_om_get_thread_id(void);
 **********************************************************************/

/*****************************************************************
* Function:     jd_om_thread_create
*
* Description:  创建线程，并设置为READY
*
* Parameters:
*               pTaskCode: 指向线程实现的指针
*               pcName: 描述性的线程名
*               pvParameters:用于修传入创建线程时需要的参数
*
* Return:
 *             JD_OM_THREAD对象:创建线程成功
*              NULL:创建线程未成功
*****************************************************************/
JD_OM_THREAD jd_om_thread_create(void * (*pTaskCode)(void*),
                                 char * pcName,
                                 void * const pvParameters);
/*****************************************************************
* Function:     jd_om_task_delete
*
* Description:  删除指定线程.
*
* Parameters:
*               JD_OM_THREAD 对象
*
* Return:
*               void
*
* 注意，这个在linux下面只能在线程结束位置调用
*****************************************************************/
osStatus jd_thread_delete(JD_OM_THREAD );

/*****************************************************************
* Function:     jd_om_get_thread_id
*
* Description:  获取当前线程id.
*
* Parameters:
*               void
* Return:
*               void*
* droped!!
*****************************************************************/

void * jd_om_get_thread_id(void);

/*****************************************************************
* Function:     jd_om_thread_sleep
*
* Description:  线程阻塞.
*
* Parameters:
*               msec：阻塞的时间
*
* Return:
*               void
*
*****************************************************************/
void jd_om_thread_delay(int msec);

/*********************** TIMER Management *****************************
 *
 *
 **********************************************************************/



 /*****************************************************************
 * Function:     jd_om_timer_init
 *
 * Description:  定时器初始化.
 *
 * Parameters:
 *              usec：定时器初始化的精度
 *
 * Return:
  *              int:timer id
 *
 *****************************************************************/
void jd_om_timer_init(int usec);

 /*****************************************************************
 * Function:     jd_om_timer_create
 *
 * Description:  创建定时器.
 *
 * Parameters:
 *               usec:定时器时间
 *               timer_cb_func：callback 函数
 * Return:
 *              JD_OM_TIMER 全局对象
 *
  * 说明: usec 必须是 jd_om_timer_init 中usec 的整数倍，否则定时不准确
 *****************************************************************/
 JD_OM_TIMER jd_om_timer_create(int usec,void (*timer_cb_func)(JD_OM_TIMER timer_id));

 /*****************************************************************
 * Function:     jd_om_timer_start
 *
 * Description:  启动定时器.
 *
 * Parameters:
  *              timer_id:JD_OM_TIMER
 *               repeat:是否重复启动
 * Return:
 *              osStatus
 *
 *****************************************************************/
 osStatus jd_om_timer_start(JD_OM_TIMER timer_id,int repeat);

 /*****************************************************************
 * Function:     jd_om_timer_stop
 *
 * Description:  启动定时器.
 *
 * Parameters:
  *              timer_id:JD_OM_TIMER
 *
 * Return:
 *              osStatus
 *
 *****************************************************************/
 osStatus jd_om_timer_stop(JD_OM_TIMER timer_id);
// int jd_om_timer_sts(JD_OM_TIMER timer_id);

 /*****************************************************************
 * Function:     jd_om_timer_delete
 *
 * Description:  删除定时器.
 *
 * Parameters:
  *              timer_id:JD_OM_TIMER
 *
 * Return:
 *              osStatus
 *
 *****************************************************************/
 osStatus jd_om_timer_delete(JD_OM_TIMER timer_id);


/*********************** Mutex Management *****************************
*
*
**********************************************************************/

/*****************************************************************
* Function:     jd_om_mutex_create
*
* Description:  创建互斥锁.
*
* Parameters:
*              void
*
 * Return:
 *             JD_OM_MUTEX 对象
 *             返回 NULL 失败
*
*****************************************************************/
JD_OM_MUTEX jd_om_mutex_create(void);

/*****************************************************************
* Function:     jd_om_mutex_lock
*
* Description:  锁.
*
* Parameters:
*
*              JD_OM_MUTEX 对象
*
* Return:
*              osStatus
*
*
*****************************************************************/
osStatus jd_om_mutex_lock(JD_OM_MUTEX);

/*****************************************************************
* Function:     jd_om_mutex_unlock
*
* Description:  释放锁.
*
* Parameters:
*              JD_OM_MUTEX 对象
*
* Return:
*              osStatus
*
*****************************************************************/
osStatus jd_om_mutex_unlock(JD_OM_MUTEX);

/*****************************************************************
* Function:     jd_om_mutex_delete
*
* Description:  删除互斥锁.
*
* Parameters:
*              JD_OM_MUTEX 对象
*
* Return:
*              osStatus
*
*****************************************************************/
osStatus jd_om_mutex_delete(JD_OM_MUTEX);




/*********************** Semaphore Management *****************************
*
*    osSemaphoreId jd_on_create_semaphore(int32_t count);
*    int32_t jd_om_take_semaphore(osSemaphoreId semaphore_id, uint32_t millisec);
*    osStatus jd_om_give_semaphore(osSemaphoreId semaphore_id);
*    osStatus jd_om_delete_semaphore(osSemaphoreId semaphore_id);
*
**********************************************************************/

/*****************************************************************
* Function:     jd_om_create_semaphore
*
* Description:  创建一个信号量.
*
* Parameters:
*
*
* Return:
*              JD_OM_SE 对象
*
*
*****************************************************************/

JD_OM_SEM jd_om_create_semaphore(void);

/*****************************************************************
* Function:     jd_om_take_semaphore
*
* Description:  获取一个信号量.
*
* Parameters:
*              JD_OM_SE 对象
*              millisec：等待超时
*
* Return:
*              osStatus:osOK/osErrorOS
*
*****************************************************************/
osStatus jd_om_take_semaphore(JD_OM_SEM, u32 millisec);

/*****************************************************************
* Function:     jd_om_give_semaphore
*
* Description:  释放一个信号量.
*
* Parameters:
*              JD_OM_SEM 对象
*
*
* Return:
 *              osStatus:osOK/osErrorOS
*
*****************************************************************/
osStatus jd_om_give_semaphore(JD_OM_SEM);

/*****************************************************************
* Function:     jd_om_delete_semaphore
*
* Description:  删除一个信号量.
*
* Parameters:
*              JD_OM_SEM 对象
*
*
* Return:
*              osStatus:osOK/osErrorOS
*
*****************************************************************/
osStatus jd_om_delete_semaphore(JD_OM_SEM);


/*********************** Message Queue Management *****************************
*
*    osSemaphoreId jd_on_create_semaphore(int32_t count);
*    osStatus jd_om_mq_send(osMessageQId queue_id, uint32_t info, uint32_t millisec);
*    int jd_om_mq_recv(osMessageQId queue_id, const void * buffer);
*    int jd_om_mq_peek(osMessageQId queue_id, const void * buffer);
*
**********************************************************************/

#if 1
/*****************************************************************
* Function:     jd_om_mq_create
*
* Description:  创建一个消息队列.
*
* Parameters:
 *              qsize:队列最大消息数量
*
*
* Return:
*              JD_OM_QUEUE 对象
*
*****************************************************************/
JD_OM_QUEUE jd_om_mq_create(int qsize);

/*****************************************************************
* Function:     jd_om_mq_send
*
* Description:  发送一条消息到消息队列.
*
* Parameters:
 *              queue:JD_OM_QUEUE对象
 *              pdata:数据指针
 *              lens:数据长度，可以长度是0
 *              millisec:不支持
* Return:
*              osStatus
*
*****************************************************************/
osStatus jd_om_mq_send(JD_OM_QUEUE queue,void * pdata,int lens,u32 millisec);

int jd_om_mq_destroyed(JD_OM_QUEUE queue);

/*****************************************************************
* Function:     jd_om_mq_recv
*
* Description:  从消息队列接收一条消息
*
* Parameters:
*             queue:JD_OM_QUEUE对象
*             pdata:数据指针
*             millisec = 0 阻塞模式
*             millisec > 0 查询模式
* Return:
* 		失败:
*             MQ_PEEK_EMPTY
*       成功:
*            >= 0 返回数据长度 成功
*
*****************************************************************/
int jd_om_mq_recv(JD_OM_QUEUE queue,void ** pdata,u32 millisec);

/*****************************************************************
* Function:     jd_om_mq_peek
*
* Description:  从消息队列检索一条消息，不从消息队列删除
*
* Parameters:
*             queue:JD_OM_QUEUE对象
*             index:需要检索的索引
*             pdata:数据指针
* Return:
* 		失败:
*             MQ_LOCK_ERROR 其他线程在访问，失败
*  	          MQ_PEEK_EMPTY 对应序号没有消息
*       成功:
*            >= 0 返回数据长度 成功
*
*****************************************************************/
int jd_om_mq_peek(JD_OM_QUEUE queue,int index,void ** pdata);

/*
 * jd_om_mq_remove
 * 删除消息
 * pdata: 消息指针
 * 返回值 :
 *  失败:
 * 		MQ_LOCK_ERROR 其他线程在访问，失败
 *      MQ_PEEK_EMPTY 没有消息
 *   成功:
 * 		>=0，数据长度，
 * 		如果pdata发生放是malloc ,这里调用后需要 free(pdata)
 */
// int jd_om_mq_remove(JD_OM_QUEUE queue,void ** pdata);

/*****************************************************************
* Function:     jd_om_mq_counts
*
* Description:  获取消息队列中消息个数
*
* Parameters:
*             queue:JD_OM_QUEUE对象
* Return:
* 		失败:
*             MQ_LOCK_ERROR 其他线程在访问，失败
*       成功:
*            >= 0 返回数量，成功
*
*****************************************************************/
int jd_om_mq_counts(JD_OM_QUEUE queue);


/*****************************************************************
 * Function:     jd_om_delete_mq
 *
 * Description:  删除消息队列:必须为空，不为空返回 error 必须jd_om_mq_free
 *
 * Parameters:
 *             queue:JD_OM_QUEUE对象
 * Return:
 *             osStatus
 *
 *****************************************************************/
osStatus jd_om_delete_mq(JD_OM_QUEUE p);

/*********************** Memory Pool Management *****************************
*
*     osPoolId jd_om_mem_pool_create(const osPoolDef_t *pool_def);
*     void *jd_om_mem_pool_alloc(osPoolId pool_id);
*     void *jd_om_mem_pool_calloc(osPoolId pool_id);
*     osStatus jd_om_mem_pool_free(osPoolId pool_id, void *block)
*
**********************************************************************/

void * jd_om_malloc(int size);
void jd_om_free(void* p);


/*****************************************************************
* Function:     jd_om_mem_pool_create
*
* Description:  创建并且初始化一个内存池
*
* Parameters:
*              size
*
* Return:
*              void * 申请到内存池空间的首地址
*
*****************************************************************/
//void* jd_om_mem_pool_create(int Size);

void *jd_om_mem_malloc(int Size);

/*****************************************************************
* Function:     jd_om_mem_pool_alloc
*
* Description:  从内存池申请一块内存
*
* Parameters:
*              size
*
* Return:
*              void *
*
*****************************************************************/
//void *jd_om_mem_pool_alloc(int Size);

/*****************************************************************
* Function:     jd_om_mem_pool_alloc
*
* Description:  从内存池申请一块内存，并初始化为内存为0
*
* Parameters:
*              size
*
* Return:
*              void *
*
*****************************************************************/
//void *jd_om_mem_pool_calloc(int Size);
/*****************************************************************
* Function:     jd_om_mem_pool_free
*
* Description:  释放内存块
*
* Parameters:
*
*               p：需要释放的内存的地址
*
* Return:
*              osStatus
*
*****************************************************************/
//osStatus jd_om_mem_pool_free( void *p)

/*****************************************************************
* Function:     jd_om_mem_pool_free
*
* Description:  重新分配内存
*
* Parameters:
*               size
*               p：原先内存的地址
*
* Return:
*              osStatus
*
*****************************************************************/
//void *jd_om_mem_pool_realloc(int Size, void *p);

#endif
#endif

