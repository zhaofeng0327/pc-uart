
/*
 * 设计目的:平台相关
 * linux os
 */
#include "jd_os_middleware.h"
#include <sys/time.h>
#include <signal.h>
#include <fcntl.h>
#include <termios.h>
#include <pthread.h>
#include <strings.h>
#include "ioctrl.h"


//         tlc_send/recv          tlc_send_raw/recv_raw
//android <---------------> 副控板 <-------------------->电池板

typedef struct tag_jd_om_thread {
    int priority;
	pthread_t tid;  //线程id
	char name[128];
}jd_om_thread;

typedef struct tag_jd_om_timer {

	int us;
	int reall;
	int repeat;
	int ticks;
	int ticks_max;
	int id;
	int exit;
	int stop;
	void (*timer_cb_func)(int timer_id);
	struct tag_jd_om_timer * next;
	struct tag_jd_om_timer * free;
    void * user_data;

}jd_om_timer;

typedef struct tag_jd_om_mutex {
	pthread_mutex_t mtx;
}jd_om_mutex;

typedef struct tag_jd_om_semaphore {
	//sem_t sem;
    u32 signals;
    u32 signals_read;
    pthread_cond_t cond;
    pthread_mutex_t mtx;
    pthread_mutex_t smtx;
}jd_om_semaphore;

typedef struct tag_jd_om_queue {
    sem_t sem;
    int qsize;
    void ** pdata;
    int *plens;
    u32 ridx;
    u32 widx;
    int destroy;
    //pthread_mutex_t rmtx;
    //pthread_mutex_t wmtx;
	pthread_mutex_t rwmtx;
}jd_om_queue;

static jd_om_timer global_timer;

int jd_om_comm_open(
		jd_om_comm * handle,
		char * uart_name,
		jd_om_comm_addr *local_addr,
		jd_om_comm_addr *mask_addr,
		int rate){
#if( TLC_COMM == 1 )
	// add by daitj
	int index = tpllc_set_uart_dev(uart_name);
	handle->ptlc 	= tlc_open(local_addr->addr,mask_addr->addr,index, rate);
	if(!handle->ptlc)
		return -1;
	return 0;
#endif
	return -1;
}

int jd_om_comm_close(
		jd_om_comm * handle){
#if( TLC_COMM == 1 )
	if( !handle->ptlc )
		return -1;
	return tlc_close(handle->ptlc);
#endif
	return -1;
}

int jd_om_send(	jd_om_comm * handle,
				jd_om_comm_addr * toaddr,
				void * data,
				int data_len,
				int msec){
#if( TLC_COMM == 1 )
	return tlc_send(handle->ptlc,(u8*) data, data_len, toaddr->addr);
#endif
	return -1;
}

int jd_om_recv(
		jd_om_comm * handle,
		jd_om_comm_addr *fromaddr,
		void * data,
		int data_len){
#if( TLC_COMM == 1 )
	return  tlc_recv(handle->ptlc, (u8*) data, data_len, &fromaddr->addr);
#endif
	return -1;
}

int jd_om_send_2_batt(jd_om_comm * handle, void * data, int data_len){
    //1.2.1 1
    //data[0] = 0xff;
    //data[1] = batt_id;
    //g_sw_id = batt_id;
#if( TLC_COMM == 1 )
	return tlc_send_raw(handle->ptlc,(u8*) data, data_len);
#endif
	return -1;
}

//        tlc  <--->  tlc-->write read
//android ---> master --->battery
int jd_om_recv_f_batt(jd_om_comm * handle, void * data, int data_len){
#if( TLC_COMM == 1 )
	return  tlc_recv_raw(handle->ptlc, (u8*) data, data_len);
#endif
	return -1;
    //batt_id = g_sw_id;
}


JD_OM_THREAD jd_om_thread_create(
		void* (*pTaskCode)(void*),
		char * pcName,
		void * const pvParameters){

	jd_om_thread * p = malloc(sizeof(jd_om_thread));
	if( !p )return NULL;
	bzero(p,sizeof(jd_om_thread));
	strncpy(p->name,pcName,sizeof(p->name)-1);
    
	int err = pthread_create(&p->tid, NULL, pTaskCode,pvParameters); //创建线程
	
    if(err != 0){
	    return NULL;
	}
	return (JD_OM_THREAD)p;
}

osStatus jd_thread_delete(
		JD_OM_THREAD d){
	pthread_exit(0);
	free(d);
	return 0;
}

void * jd_om_get_thread_id(void){
	return 0;
}

void jd_om_thread_delay(int msec){
	struct timeval timeOut;
	timeOut.tv_sec 	= msec/1000;//000;
	timeOut.tv_usec = 0;//msec%1000;//000;
	while( 0 != select(0, NULL, NULL, NULL, &timeOut) );
}


static jd_om_timer *  timer_find(int timer_id){
	jd_om_timer * p = global_timer.next;

	for( ; p ; p = p->next ){

		if( p->id == timer_id ){
			return p;
		}
	}
	return NULL;
}

static void timer_add(jd_om_timer * pnew){
	if( global_timer.next == NULL){
		pnew->id = global_timer.id++;
		global_timer.next = pnew;
	}else{
		jd_om_timer * p = global_timer.next;
		for( ; p != NULL ; p = p->next ){
			if( p->next == NULL )break;
		}
		pnew->id = global_timer.id++;
		p->next = pnew;
	}
}

static void timer_isr(int signo){

	jd_om_timer * p = global_timer.next;
	jd_om_timer * prev = p;
	for( ; p ; p = p->next ,prev = p ){

		if( p->exit ){
			if( !global_timer.free ){
				prev->next = p->next;
				global_timer.free = p;
				p = prev;
			}
			continue;
		}

		if( p->stop )continue;
		if( p->ticks ){
			p->ticks--;
			if (!p->ticks) {
				p->timer_cb_func(p->id);
				if (!p->reall) {
					if (p->repeat) {
						p->repeat--;
					}
					if( !p->repeat ){
						p->stop = 1;
					}
				}
				p->ticks = p->ticks_max;
			}
		}
	}
}

void jd_om_timer_init(int usec){

	struct itimerval vsec;
	signal(SIGALRM, timer_isr);
	memset(&vsec, 0, sizeof(vsec));
	vsec.it_interval.tv_sec 	= usec/(1000*1000);
	vsec.it_interval.tv_usec 	= usec%(1000*1000);
	vsec.it_value.tv_sec 		= 0;
	vsec.it_value.tv_usec 		= 100;
	bzero(&global_timer,sizeof(global_timer));

	global_timer.id = 1;
	global_timer.us = usec;

	setitimer(ITIMER_REAL, &vsec,NULL);
}

static void timer_reset(jd_om_timer * p){
	p->stop 			= 1;
	p->ticks 			= p->ticks_max;
}

JD_OM_TIMER jd_om_timer_create(
		int usec,
		void (*timer_cb_func)(int timer_id)){

	if( global_timer.free ){
		free(global_timer.free);
		global_timer.free = NULL;
	}
	jd_om_timer * p = malloc(sizeof(jd_om_timer));
	if(!p)return -1;

	bzero(p,sizeof(jd_om_timer));

	p->ticks_max 		= usec/global_timer.us;
	p->ticks 			= p->ticks_max;
	p->us 				= usec;
	p->timer_cb_func 	= timer_cb_func;
	p->stop 			= 1;
	timer_add(p);
	return p->id;
}

osStatus jd_om_timer_start(JD_OM_TIMER timer_id,int repeat){

	jd_om_timer * p = timer_find(timer_id);

	if(p){
		timer_reset(p);
		if( !repeat )
			p->reall = 1;
		else{
			p->reall = 0;
		}
		p->repeat = repeat;
		p->stop = 0;
		return osOK;
	}
	return osErrorOS;
}

osStatus jd_om_timer_stop(JD_OM_TIMER timer_id){
	jd_om_timer * p = timer_find(timer_id);
	if(p){
		p->stop = 1;
		return osOK;
	}
	return osErrorOS;
}

osStatus jd_om_timer_delete(JD_OM_TIMER timer_id){
	jd_om_timer * p = timer_find(timer_id);
	if(p){
		p->exit = 1;
		return osOK;
	}
	return osErrorOS;
}

JD_OM_MUTEX jd_om_mutex_create(void){
    
	jd_om_mutex * p = malloc(sizeof(jd_om_mutex));
    if(!p)return NULL;
    bzero(p,sizeof(jd_om_mutex));
	if( 0 != pthread_mutex_init( &p->mtx ,NULL) ){
		return NULL;
	}
	return (JD_OM_MUTEX)p;
}

osStatus jd_om_mutex_lock(JD_OM_MUTEX  mutex ){
    if( 0 ==  pthread_mutex_lock( &(((jd_om_mutex*)mutex)->mtx)) ){
        return osOK;
    }
    return osErrorOS;
}

osStatus jd_om_mutex_unlock(JD_OM_MUTEX mutex){
    if( 0 == pthread_mutex_unlock( &(((jd_om_mutex*)mutex)->mtx)) ){
        return osOK;
    }
    return osErrorOS;
}

osStatus jd_om_mutex_delete(JD_OM_MUTEX mutex){
	pthread_mutex_destroy(&((jd_om_mutex*)mutex)->mtx);
	return 1;
}

JD_OM_SEM jd_om_create_semaphore(void){

    int mtx = 0;
	jd_om_semaphore * p = malloc(sizeof(jd_om_semaphore));
	if(!p)goto error;
    bzero(p,sizeof(jd_om_semaphore));
    if( 0 != pthread_mutex_init( &p->mtx,NULL) ){
        goto error;
    }
    mtx++;
    if( 0 != pthread_mutex_init( &p->smtx,NULL) ){
        goto error;
    }
    mtx++;
    pthread_condattr_t cattr;
    if (0 != pthread_condattr_init(&cattr) ){
        goto error;
    }
    pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
    if( 0 != pthread_cond_init(&p->cond, &cattr) ){
        goto error;
    }

    p->signals = 0;
    p->signals_read = 0;
	return (void*)p;
error:
    if(p){
        free(p);
        if(mtx > 0)pthread_mutex_destroy(&p->mtx);
        if(mtx == 2)pthread_mutex_destroy(&p->smtx);
    }
    return NULL;
}

#define VPSEM(sem) ((jd_om_semaphore *)sem)

osStatus jd_om_give_semaphore(JD_OM_SEM p){
    if(  (u32)(VPSEM(p)->signals - VPSEM(p)->signals_read ) > (u32)(0xffffffff-2) ){
        return osErrorOS;
    }
    pthread_mutex_lock( &(VPSEM(p)->smtx) );
    VPSEM(p)->signals++;
    pthread_cond_signal(&(VPSEM(p)->cond));
    pthread_mutex_unlock(&(VPSEM(p)->smtx));
    return osOK;
}

osStatus jd_om_take_semaphore(JD_OM_SEM p,u32 millisec){
    
    osStatus ret = osErrorOS;
    pthread_mutex_lock(&(VPSEM(p)->mtx));
    if( VPSEM(p)->signals_read != VPSEM(p)->signals ){
    	VPSEM(p)->signals_read++;
        ret = osOK;
    }else{
        if( millisec == 0 ){
             pthread_cond_wait( &(VPSEM(p)->cond), &(VPSEM(p)->mtx));
        }else{
            struct timespec tv;
            clock_gettime(CLOCK_MONOTONIC, &tv);
            tv.tv_sec += millisec/1000;
            tv.tv_nsec += (millisec%1000)*10000000;
            pthread_cond_timedwait(&(VPSEM(p)->cond), &(VPSEM(p)->mtx),&tv);
        }
        if( VPSEM(p)->signals_read != VPSEM(p)->signals ){
        	VPSEM(p)->signals_read++;
            ret = osOK;
        }else{
            ret = osErrorOS;
        }
    }
    pthread_mutex_unlock(&(VPSEM(p)->mtx));
	return ret;
}

osStatus jd_om_delete_semaphore(JD_OM_SEM p){
    if(!p)
        return osErrorOS;
    pthread_mutex_destroy(&(VPSEM(p)->mtx));
    pthread_mutex_destroy(&(VPSEM(p)->smtx));
    free(p);
	return osOK;
}


#define VPMQ(queue) ((jd_om_queue *)queue)
JD_OM_QUEUE jd_om_mq_create(int qsize){
    
    jd_om_queue * p = malloc(sizeof(jd_om_queue));
    if( !p )return NULL;
    bzero(p,sizeof(jd_om_queue));



    p->qsize = qsize;
    p->pdata = malloc(p->qsize*sizeof(void*));
    if( !p->pdata ){
        free(p);
        return NULL;
    }
    p->plens = malloc(p->qsize*sizeof(int));
    if( !p->plens ){
        free(p->pdata);
        free(p);
        return NULL;
    }
    //pthread_mutex_init( &p->rmtx,NULL);
    //pthread_mutex_init( &p->wmtx,NULL);
    pthread_mutex_init( &p->rwmtx,NULL);

    sem_init(&p->sem,0,0);
    p->ridx = p->widx = 0;
    return (JD_OM_QUEUE)p;
}

osStatus jd_om_mq_send(JD_OM_QUEUE queue,
                       void * pdata,
                       int lens,
                       u32 millisec){

    jd_om_queue * p = (jd_om_queue*)queue;
    if(p->destroy)
        return osErrorOS;



    pthread_mutex_lock(&p->rwmtx);
    if( (u32)( p->widx - p->ridx ) >= (p->qsize-2) ){
        pthread_mutex_unlock(&p->rwmtx);
        sem_post(&p->sem);
        jd_om_thread_delay(1);
        return osErrorOS;
    }
    p->plens[p->widx%p->qsize] = lens;
    p->pdata[p->widx%p->qsize] = pdata;
    p->widx++;
    pthread_mutex_unlock(&p->rwmtx);
    sem_post(&p->sem);
    return osOK;
}



int jd_om_mq_peek(JD_OM_QUEUE queue,int index,void ** pdata){
	jd_om_queue * p = (jd_om_queue*)queue;

	if( p->ridx == p->widx )
		return MQ_PEEK_EMPTY;
	if( 0 != pthread_mutex_trylock(&p->rwmtx) ){
		return MQ_LOCK_ERROR;
	}
	u32 ridx = p->ridx;
	for(;ridx!=p->widx;ridx++){
		if(!index)break;
		index--;
	}
	if( index ){
		pthread_mutex_unlock(&p->rwmtx);
		return MQ_PEEK_EMPTY;
	}
	*pdata = p->pdata[ridx%p->qsize];
	int lens = p->plens[ridx%p->qsize];
	pthread_mutex_unlock(&p->rwmtx);
	return lens;
}

int jd_om_mq_remove(JD_OM_QUEUE queue,void ** pdata){
	jd_om_queue * p = (jd_om_queue*)queue;
	if( 0 != pthread_mutex_trylock(&p->rwmtx) ){
		return MQ_LOCK_ERROR;
	}
	int lens =0;
	if( p->ridx != p->widx ){
		*pdata = p->pdata[p->ridx%p->qsize];
		lens = p->plens[p->ridx%p->qsize];
		p->ridx++;
	}else{
		lens = MQ_PEEK_EMPTY;
	}
	pthread_mutex_unlock(&p->rwmtx);
	return lens;
}

int jd_om_mq_counts(JD_OM_QUEUE queue){
	jd_om_queue * p = (jd_om_queue*)queue;
	if( 0 != pthread_mutex_trylock(&p->rwmtx) ){
		return MQ_LOCK_ERROR;
	}
	u32 counts = (p->widx - p->ridx);
	pthread_mutex_unlock(&p->rwmtx);
	return counts;
}

int jd_om_mq_destroyed(JD_OM_QUEUE queue)
{
	jd_om_queue * p = (jd_om_queue*)queue;
	return p->destroy;
}

int jd_om_mq_recv(JD_OM_QUEUE queue,
                       void ** pdata,
                       u32 millisec){
    jd_om_queue * p = (jd_om_queue*)queue;
    while( !p->destroy ){
    	pthread_mutex_lock(&p->rwmtx);
        if( p->ridx != p->widx ){
            *pdata = p->pdata[p->ridx%p->qsize];
            int lens = p->plens[p->ridx%p->qsize];
            p->ridx++;
            pthread_mutex_unlock(&p->rwmtx);
            return lens;
        }
        pthread_mutex_unlock(&p->rwmtx);
        if( millisec != 0 ){
        	sem_trywait(&p->sem);
        	break;
        }else{
        	sem_wait(&p->sem);
        }
    }
    return MQ_PEEK_EMPTY;
}

osStatus jd_om_delete_mq(JD_OM_QUEUE queue){
	jd_om_queue * p = (jd_om_queue*)queue;
    if(!p){
        return osErrorOS;
    }
    p->destroy = 1;
    sem_post(&p->sem);
    sem_post(&p->sem);
    usleep(1000*10);
    //pthread_mutex_destroy(&p->rmtx);
    //pthread_mutex_destroy(&p->wmtx);
	pthread_mutex_destroy(&p->rwmtx);

    free(p->plens);
    free(p->pdata);
    sem_destroy(&p->sem);
    free(p);
    return osOK;
}

void * jd_om_malloc(int size){
	return malloc(size);
}

void jd_om_free(void* p){
	free(p);
}

