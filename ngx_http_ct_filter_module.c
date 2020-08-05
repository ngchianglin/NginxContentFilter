/****************************************************
 *
 * Nginx Content Filter Module
 *
 * This is an nginx filter module that can filter and block sensitive content
 * such as NRIC numbers, mobile numbers etc... using pcre regular expression.
 * The module filters HTTP response body using regular expressions specified
 * through nginx configuration directives. Matching is done on a line by
 * line basis.
 *
 * When matches are detected in the HTTP response body,
 * it will log an alert and display a blank empty page instead of the
 * original content. This can prevent sensitive content being leaked.
 *
 * The module can be an additional layer of defense against malicious
 * web attacks.
 *
 * A logging only mode is also available. This can be useful for troubleshooting
 * without blocking actual web content.
 *
 * Note if the HTTP response body size is more than NGX_HTTP_CT_MAX_CONTENT_SZ
 * or 10MB, the module will skip processing and let the content pass through.
 * Note the size limit doesn't apply for HTTP Trunked Transfer Encoding.
 * Compressed content will also be skipped by the module. 
 * 
 * Refer to the README file for instructions on setup and usage.
 *
 * The module is based on a fork of Weibin Yao(yaoweibin@gmail.com)
 * substitution module. Refer to the following github link
 * for the original substitution module.
 * https://github.com/yaoweibin/ngx_http_substitutions_filter_module
 *
 *
 *
 * Ng Chiang Lin
 * May 2018
 *
 *
 * Copyright (C) 2018 by Ng Chiang Lin
 * Copyright (C) 2014 by Weibin Yao <yaoweibin@gmail.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 ****************************************************/


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


#if (NGX_DEBUG)
#define CONTF_DEBUG 1
#else
#define CONTF_DEBUG 0
#endif

#ifndef NGX_HTTP_MAX_CAPTURES
#define NGX_HTTP_MAX_CAPTURES 9
#endif

#define NGX_HTTP_CT_MAX_CONTENT_SZ 1024 * 1024 * 10
#define NGX_HTTP_CT_BUF_SIZE 4096

#define ngx_buffer_init(b) b->pos = b->last = b->start;


typedef struct {
     ngx_str_t      match;
#if (NGX_PCRE)
    ngx_regex_t   *match_regex;
    int           *captures;
    ngx_int_t      ncaptures;
#endif
    unsigned int    occurence;
    unsigned int    matched;
} blk_pair_t;



typedef struct {
    ngx_hash_t     types;
    ngx_array_t   *blk_pairs; /* array of blk_pair_t */
    ngx_array_t   *types_keys;  /* array of ngx_hash_key_t */
    ngx_flag_t    logonly;   /* flag to indicate logging only */
    size_t         line_buffer_size;
    ngx_bufs_t     bufs;
} ngx_http_ct_loc_conf_t;


typedef struct {
    ngx_array_t   *blk_pairs; /* array of blk_pair_t */
    ngx_flag_t    logonly;   /* flag to indicate logging only */
    ngx_chain_t   *in;

    /* the line input buffer before substitution */
    ngx_buf_t     *line_in;

    /* the last output buffer */
    ngx_buf_t     *out_buf;
    /* point to the last output chain's next chain */
    ngx_chain_t  **last_out;
    ngx_chain_t   *out;

    ngx_chain_t   *busy;

    /* the freed chain buffers. */
    ngx_chain_t   *free;

    ngx_int_t      bufs;

    unsigned       last;
    unsigned int    matched;

} ngx_http_ct_ctx_t;



static char * ngx_http_ct_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_ct_filter_regex_compile(blk_pair_t *pair,
    ngx_conf_t *cf);
static ngx_int_t ngx_http_ct_match(ngx_http_request_t *r,
    ngx_http_ct_ctx_t *ctx);
static ngx_int_t ngx_http_ct_body_filter_process_buffer(ngx_http_request_t *r,
    ngx_buf_t *b);
static ngx_int_t ngx_test_ct_compression(ngx_http_request_t *r);


static ngx_int_t ngx_http_ct_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_ct_init_context(ngx_http_request_t *r);
static ngx_int_t ngx_http_ct_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_ct_body_filter_init_context(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_buf_t * buffer_append_string(ngx_buf_t *b, u_char *s, size_t len,
    ngx_pool_t *pool);
static ngx_int_t  ngx_http_ct_out_chain_append(ngx_http_request_t *r,
    ngx_http_ct_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t  ngx_http_ct_get_chain_buf(ngx_http_request_t *r,
    ngx_http_ct_ctx_t *ctx);
static ngx_int_t ngx_http_ct_output(ngx_http_request_t *r,
    ngx_http_ct_ctx_t *ctx, ngx_chain_t *in);
static void *ngx_http_ct_create_conf(ngx_conf_t *cf);
static char *ngx_http_ct_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_ct_filter_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_ct_send_empty(ngx_http_request_t *r,
  ngx_http_ct_ctx_t *ctx);

#if (NGX_PCRE)
static ngx_int_t ngx_http_ct_regex_capture_count(ngx_regex_t *re);
#endif


static ngx_command_t  ngx_http_ct_filter_commands[] = {

      { ngx_string("ct_filter"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_ct_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ct_filter_logonly"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ct_loc_conf_t,logonly),
      NULL },

    { ngx_string("ct_filter_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ct_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("ct_line_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ct_loc_conf_t, line_buffer_size),
      NULL },

    { ngx_string("ct_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ct_loc_conf_t, bufs),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_ct_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_ct_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ct_create_conf,             /* create location configuration */
    ngx_http_ct_merge_conf               /* merge location configuration */
};


ngx_module_t  ngx_http_ct_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_ct_filter_module_ctx,      /* module context */
    ngx_http_ct_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

extern volatile ngx_cycle_t  *ngx_cycle;


static ngx_int_t
ngx_http_ct_header_filter(ngx_http_request_t *r)
{
  
    ngx_http_ct_loc_conf_t  *slcf;


    slcf = ngx_http_get_module_loc_conf(r, ngx_http_ct_filter_module);

    if(slcf == NULL)
    {
        return ngx_http_next_header_filter(r);
    }


    if (slcf->blk_pairs == NULL
        || slcf->blk_pairs->nelts == 0
        || r->header_only
        || r->headers_out.content_type.len == 0
        || r->headers_out.content_type.len > NGX_HTTP_CT_MAX_CONTENT_SZ)
    {
        return ngx_http_next_header_filter(r);
    }


    if (ngx_http_test_content_type(r, &slcf->types) == NULL) {
        return ngx_http_next_header_filter(r);
    }

    //Check for compressed content
    if(ngx_test_ct_compression(r) != 0)
    {//Compression enabled, don't filter
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                     "[Content filter]: ngx_http_ct_header_filter"
                     " compression enabled skipping");
        return ngx_http_next_header_filter(r);
    }

    #if CONTF_DEBUG
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "[Content filter]: http content filter header \"%V\"", &r->uri);
    #endif

    if (ngx_http_ct_init_context(r) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     "[Content filter]: ngx_http_ct_header_filter"
                     " cannot initialize request ctx");
        return NGX_ERROR;
    }

    r->filter_need_in_memory = 1;

    return ngx_http_next_header_filter(r);

}


static ngx_int_t
ngx_http_ct_init_context(ngx_http_request_t *r)
{
    ngx_uint_t                 i;
    blk_pair_t                *src_blk_pair, *dst_blk_pair;
    ngx_http_ct_ctx_t       *ctx;
    ngx_http_ct_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_ct_filter_module);

    if(slcf == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     "[Content filter]: ngx_http_ct_init_context"
                     " cannot initalize request context "
                     "slcf config not available");
        return NGX_ERROR;
    }

    /* Everything in ctx is NULL or 0. */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ct_ctx_t));
    if (ctx == NULL) {
         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     "[Content filter]: ngx_http_ct_init_context"
                     " cannot initialize memory "
                     "for request context");
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_ct_filter_module);

    if(slcf->blk_pairs != NULL)
    {
         /* Deep copy blk_pairs from slcf to ctx  */
        ctx->blk_pairs = ngx_array_create(r->pool, slcf->blk_pairs->nelts,
                                          sizeof(blk_pair_t));
        if(ctx->blk_pairs == NULL)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     "[Content filter]: ngx_http_ct_init_context"
                     " cannot initialize memory "
                     "for ctx blk_pairs");
            return NGX_ERROR;
        }

        src_blk_pair = (blk_pair_t *) slcf->blk_pairs->elts;

        for (i = 0; i < slcf->blk_pairs->nelts; i++) {

            dst_blk_pair = ngx_array_push(ctx->blk_pairs);
            if (dst_blk_pair == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     "[Content filter]: ngx_http_ct_init_context"
                     " cannot initialize array "
                     "for ctx blk_pair");
                return NGX_ERROR;
            }

            ngx_memcpy(dst_blk_pair, src_blk_pair + i, sizeof(blk_pair_t));
        }
    }

    if(slcf->logonly)
    {
        ctx->logonly = slcf->logonly;
    }

    if (ctx->line_in == NULL) {

        ctx->line_in = ngx_create_temp_buf(r->pool, slcf->line_buffer_size);
        if (ctx->line_in == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     "[Content filter]: ngx_http_ct_init_context"
                     " cannot initialize memory "
                     "for ctx line_in");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ct_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t    	          rc;
    ngx_log_t               *log;
    ngx_chain_t             *cl;
    ngx_http_ct_ctx_t       *ctx;
    ngx_http_ct_loc_conf_t  *slcf;

    log = r->connection->log;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_ct_filter_module);
    if (slcf == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ct_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    #if CONTF_DEBUG
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "[Content filter]: ngx_http_ct_body_filter http content filter \"%V\"", &r->uri);
    #endif

    if (in == NULL && ctx->busy == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ngx_http_ct_body_filter_init_context(r, in) != NGX_OK) {
        goto failed;
    }

    for (cl = ctx->in; cl; cl = cl->next) {

        if (cl->buf->last_buf || cl->buf->last_in_chain) {
            ctx->last = 1;
        }

        /* Process each buffer for sensitive content matching */
        rc = ngx_http_ct_body_filter_process_buffer(r, cl->buf);

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, log, 0,  "[Content filter]: "
                "ngx_http_ct_body_filter error procesing buffer"
                " for sensitive content");
            goto failed;
        }

        if (ctx->last)
        {//last buffer set the last_buf or last_in_chain flag
         //for the last output buffer
            if (ctx->out_buf == NULL) {
                if (ngx_http_ct_get_chain_buf(r, ctx) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                              "[Content filter]: ngx_http_ct_body_filter "
                              "cannot get buffer for out_buf");
                    return NGX_ERROR;
              }
            }

            if( ngx_buf_size(ctx->out_buf) == 0)
            {//last buffer is zero size
                 ctx->out_buf->sync = 1;
            }

            ctx->out_buf->last_buf = (r == r->main) ? 1 : 0;
            ctx->out_buf->last_in_chain = cl->buf->last_in_chain;
            break;
        }

    }

    /* It doesn't output anything, return */
    if ((ctx->out == NULL) && (ctx->busy == NULL)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                     "[Content filter]: ngx_http_ct_body_filter nothing to output");
        return NGX_OK;
    }

    /*If sensitive content is detected */
    if(ctx->matched && ctx->last)
    {
         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "[Content filter]: Alert ! Sensitive content is detected !");

        if(!ctx->logonly)
        { //logonly is not enabled. Show empty page.
           return ngx_http_ct_send_empty(r,ctx);
        }

    }

    return ngx_http_ct_output(r, ctx, in);

failed:

    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "[Content filter]: ngx_http_ct_body_filter error.");

    return NGX_ERROR;
}

static ngx_int_t
ngx_http_ct_send_empty(ngx_http_request_t *r, ngx_http_ct_ctx_t *ctx)
{

     u_char        *empty_content;
     size_t        i, quotient, remainder;
     ngx_buf_t     *b;
     ngx_int_t     rc;
     ngx_uint_t    content_length = 0;
     ngx_chain_t   *cl, **ll;


     content_length = r->headers_out.content_length_n;

     /* Ensure that content length is a sane value */
    if (r->headers_out.content_length_n == -1
        || content_length > NGX_HTTP_CT_MAX_CONTENT_SZ)
    {

        content_length = NGX_HTTP_CT_BUF_SIZE;
        /* Fall back to keepalive = 0 */
        r->keepalive = 0;
    }

   quotient = content_length / NGX_HTTP_CT_BUF_SIZE;
   remainder = content_length % NGX_HTTP_CT_BUF_SIZE;

   if (remainder > 0)
   {
       quotient = quotient + 1;
   }

   empty_content = ngx_pcalloc(r->pool, sizeof(u_char) * NGX_HTTP_CT_BUF_SIZE);

   if (empty_content == NULL)
   {
       ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
           "[Content filter]: ngx_http_ct_send_empty: "
           "unable to allocate empty content memory");
       return NGX_ERROR;
   }

   ll = &ctx->out;
   for (i = 0; i < quotient; i++) {

      cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
      if (cl == NULL) {
           ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
               "[Content filter]: ngx_http_ct_send_empty: "
               "unable to allocate output chain memory");
           return NGX_ERROR;
      }

      b = cl->buf ;
      ngx_memzero(b, sizeof(ngx_buf_t));

      b->tag = (ngx_buf_tag_t) &ngx_http_ct_filter_module;
      b->memory = 1;
      b->pos = empty_content;
      b->last = empty_content + (sizeof(u_char) * NGX_HTTP_CT_BUF_SIZE);
      b->start = b->pos;
      b->end = b->last;
      b->recycled = 1;
      b->last_buf = 0;
      b->last_in_chain = 0;

      if (i == (quotient - 1)) {
       /* last iteration */
       /* Set the content size to the remaining remainder */
         b->last = empty_content + remainder;
         b->last_buf = (r == r->main) ? 1: 0;
         b->last_in_chain = 1;
      }

      *ll = cl;
      ll = &cl->next;

   }

  rc = ngx_http_next_body_filter(r, ctx->out);
  ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
        (ngx_buf_tag_t)&ngx_http_ct_filter_module);

  /*Send empty means no more output expected*/
  r->connection->buffered &= ~NGX_HTTP_SUB_BUFFERED;

  return rc;

}

static ngx_int_t
ngx_http_ct_body_filter_init_context(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_ct_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ct_filter_module);

    r->connection->buffered |= NGX_HTTP_SUB_BUFFERED;

    ctx->in = NULL;

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[Content filter]: ngx_http_ct_body_filter_init_context "
                      " Cannot copy incoming chains to ctx->in");
            return NGX_ERROR;
        }
    }

#if CONTF_DEBUG
    if (ngx_buf_size(ctx->line_in) > 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "[Content filter]: subs line in buffer: %p, size:%uz",
                       ctx->line_in, ngx_buf_size(ctx->line_in));
    }
#endif

#if CONTF_DEBUG
    ngx_chain_t               *cl;

    for (cl = ctx->in; cl; cl = cl->next) {
        if (cl->buf) {
            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "[Content filter]: subs in buffer:%p, size:%uz, "
                           "flush:%d, last_buf:%d",
                           cl->buf, ngx_buf_size(cl->buf),
                           cl->buf->flush, cl->buf->last_buf);
        }
    }
#endif

    if(ctx->out == NULL)
    {
        ctx->last_out = &ctx->out;
    }

    return NGX_OK;
}


static ngx_buf_t *
buffer_append_string(ngx_buf_t *b, u_char *s, size_t len, ngx_pool_t *pool)
{
    u_char     *p;
    ngx_uint_t capacity, size;

    if (len > (size_t) (b->end - b->last)) {

        size = b->last - b->pos;

        capacity = b->end - b->start;
        capacity <<= 1;

        if (capacity < (size + len)) {
            capacity = size + len;
        }

        p = ngx_palloc(pool, capacity);
        if (p == NULL) {
            return NULL;
        }

        b->last = ngx_copy(p, b->pos, size);

        b->start = b->pos = p;
        b->end = p + capacity;
    }

    b->last = ngx_copy(b->last, s, len);

    return b;
}


static ngx_int_t
ngx_http_ct_out_chain_append(ngx_http_request_t *r,
    ngx_http_ct_ctx_t *ctx, ngx_buf_t *b)
{
    size_t       len, capcity;

    if (b == NULL) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[Content filter]: ngx_http_ct_out_chain_append "
                      "input buffer is null");

        return NGX_ERROR;
    }

    if (ctx->out_buf == NULL) {
       if (ngx_http_ct_get_chain_buf(r, ctx) != NGX_OK) {
           ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[Content filter]: ngx_http_ct_out_chain_append "
                      "cannot get buffer");
           return NGX_ERROR;
       }
    }

    while (1) {

        len = (size_t) ngx_buf_size(b);
        if (len == 0) {
            break;
        }

        capcity = ctx->out_buf->end - ctx->out_buf->last;

        if (len <= capcity) {
            ctx->out_buf->last = ngx_copy(ctx->out_buf->last, b->pos, len);
            b->pos += len;
            break;

        } else {
            ctx->out_buf->last = ngx_copy(ctx->out_buf->last,
                                          b->pos, capcity);
        }

        b->pos += capcity;

        /* get more buffers */
        if (ngx_http_ct_get_chain_buf(r, ctx) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[Content filter]: ngx_http_ct_out_chain_append "
                      "cannot get buffer");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ct_get_chain_buf(ngx_http_request_t *r,
    ngx_http_ct_ctx_t *ctx)
{
    ngx_chain_t               *temp;
    ngx_http_ct_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_ct_filter_module);

    if (ctx->free) {
        temp = ctx->free;
        ctx->free = ctx->free->next;

    } else {
        temp = ngx_alloc_chain_link(r->pool);
        if (temp == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[Content filter]: ngx_http_ct_get_chain_buf "
                      "cannot allocate chain");
            return NGX_ERROR;
        }

        temp->buf = ngx_create_temp_buf(r->pool, slcf->bufs.size);
        if (temp->buf == NULL) {
             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[Content filter]: ngx_http_ct_get_chain_buf "
                      "cannot allocate buffer");
            return NGX_ERROR;
        }

        temp->buf->tag = (ngx_buf_tag_t) &ngx_http_ct_filter_module;
        temp->buf->recycled = 1;

        /* TODO: limit the buffer number */
        ctx->bufs++;
    }

    temp->next = NULL;

    ctx->out_buf = temp->buf;
    *ctx->last_out = temp;
    ctx->last_out = &temp->next;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ct_output(ngx_http_request_t *r, ngx_http_ct_ctx_t *ctx,
                     ngx_chain_t *in)
{
    ngx_int_t     rc;

#if CONTF_DEBUG
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    for (cl = ctx->out; cl; cl = cl->next) {

        b = cl->buf;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "[Content filter]: subs out buffer:%p, size:%uz, t:%d, l:%d",
                       b, ngx_buf_size(b), b->temporary, b->last_buf);
    }
#endif


    if(ctx->last)
    {

        #if CONTF_DEBUG
             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "[Content filter]: subs out buffer: last buffer"
                       );
        #endif


        /* ctx->out may not output all the data */
        rc = ngx_http_next_body_filter(r, ctx->out);
        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "[Content filter]: ngx_http_ct_output "
                            "nginx next body filter returns error");
            return NGX_ERROR;
        }
    }
    else
    {
        #if CONTF_DEBUG
             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "[Content filter]: subs out buffer: not last return NGX_OK"
                       );
        #endif

        return NGX_OK;
    }

#if CONTF_DEBUG
    for (cl = ctx->out; cl; cl = cl->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "[Content filter]: subs out end: %p %uz", cl->buf, ngx_buf_size(cl->buf));
    }
#endif

#if defined(nginx_version) && (nginx_version >= 1001004)
    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                            (ngx_buf_tag_t) &ngx_http_ct_filter_module);
#else
    ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->out,
                            (ngx_buf_tag_t) &ngx_http_ct_filter_module);
#endif

    if (ctx->last) {
        r->connection->buffered &= ~NGX_HTTP_SUB_BUFFERED;
    }

    return rc;
}




#if (NGX_PCRE)
static ngx_int_t
ngx_http_ct_regex_capture_count(ngx_regex_t *re)
{
    int rc, n;

    n = 0;

#if defined(nginx_version) && nginx_version >= 1002002
    rc = pcre_fullinfo(re->code, NULL, PCRE_INFO_CAPTURECOUNT, &n);
#elif defined(nginx_version) && nginx_version >= 1001012
    rc = pcre_fullinfo(re->pcre, NULL, PCRE_INFO_CAPTURECOUNT, &n);
#else
    rc = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &n);
#endif

    if (rc < 0) {
        return (ngx_int_t) rc;
    }

    return (ngx_int_t) n;
}
#endif


static void *
ngx_http_ct_create_conf(ngx_conf_t *cf)
{
    ngx_http_ct_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ct_loc_conf_t));
    if (conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "[Content filter]: Cannot allocate config memory");
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->blk_pairs = NULL;
     *     conf->types = {NULL, 0};
     *     conf->types_keys = NULL;
     *     conf->bufs.num = 0;
     */

    conf->line_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->logonly = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_ct_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ct_loc_conf_t *prev = parent;
    ngx_http_ct_loc_conf_t *conf = child;


    ngx_conf_merge_value(conf->logonly, prev->logonly, 0);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "[Content filter]: ngx_http_ct_merge_conf cannot "
                         "merge html types");
        return NGX_CONF_ERROR;
    }

    #if CONTF_DEBUG
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "[Content filter]: ngx_http_ct_merge_conf value of "
                         "ngx_pagesize : %ui", ngx_pagesize);
    #endif


    ngx_conf_merge_size_value(conf->line_buffer_size,
                              prev->line_buffer_size, 8 * ngx_pagesize);

    /* Default total buffer size is 128k */
    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);

    #if CONTF_DEBUG
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "[Content filter]: ngx_http_ct_merge_conf  "
                         "line buffer size : %uz", conf->line_buffer_size);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "[Content filter]: ngx_http_ct_merge_conf  "
                         "buffer setting num: %i , size: %uz",
                         conf->bufs.num, conf->bufs.size);
    #endif


    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ct_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ct_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_ct_body_filter;

    return NGX_OK;
}



static char *
ngx_http_ct_filter( ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                   n;
    ngx_str_t                  *value;
    ngx_str_t                  occurence_str;
    blk_pair_t                 *pair;
    ngx_http_ct_loc_conf_t   *slcf = conf;


    #if !(NGX_PCRE)
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "[Content filter]: Error PCRE library is required !");
        return NGX_CONF_ERROR;
    #endif


    if (cf->args->nelts < 2){

       ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "[Content filter]: ngx_http_ct_filter invalid "
                            "configuration arguments");
       return NGX_CONF_ERROR;
    }


    value = cf->args->elts;

    if (slcf->blk_pairs == NULL) {
        slcf->blk_pairs = ngx_array_create(cf->pool, 4, sizeof(blk_pair_t));
        if (slcf->blk_pairs == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "[Content filter]: ngx_http_ct_filter cannot allocate memory "
                            " for blk_pairs");
            return NGX_CONF_ERROR;
        }
    }

    pair = ngx_array_push(slcf->blk_pairs);
    if (pair == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "[Content filter]: ngx_http_ct_filter cannot allocate array"
                            " for blk_pairs");
        return NGX_CONF_ERROR;
    }
    ngx_memzero(pair, sizeof(blk_pair_t));


    n = ngx_http_script_variables_count(&value[1]);
    if (n != 0) {

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "[Content filter]: ngx_http_ct_filter match part cannot"
                               " contain variable");
        return NGX_CONF_ERROR;

    } else {
        pair->match = value[1];
    }

    occurence_str = value[2];
    n = ngx_atoi(occurence_str.data, occurence_str.len);
    if(n == NGX_ERROR || n <= 0)
    {
       ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "[Content filter]: ngx_http_ct_filter invalid argument occurence");
       return NGX_CONF_ERROR;
    }

    pair->occurence = (unsigned int) n;


    if (ngx_http_ct_filter_regex_compile(pair, cf) == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "[Content filter]: ngx_http_ct_filter cannot compile regex");
        return NGX_CONF_ERROR;
    }


    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ct_filter_regex_compile(blk_pair_t *pair, ngx_conf_t *cf)
{

#if (NGX_PCRE)
    u_char            errstr[NGX_MAX_CONF_ERRSTR];
    ngx_int_t         n, options;
    ngx_str_t         err;

    err.len = NGX_MAX_CONF_ERRSTR;
    err.data = errstr;

    //Always set to case insensitive matching
    options =  NGX_REGEX_CASELESS;


    ngx_regex_compile_t   rc;

    rc.pattern = pair->match;
    rc.pool = cf->pool;
    rc.err = err;
    rc.options = options;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[Content filter]: "
            "ngx_http_ct_filter_regex_compile %V", &rc.err);
        return NGX_ERROR;
    }

    pair->match_regex = rc.regex;

    if (pair->match_regex == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[Content filter]: "
            "ngx_http_ct_filter_regex_compile %V", &err);
        return NGX_ERROR;
    }

    n = ngx_http_ct_regex_capture_count(pair->match_regex);


    //Make sure that it doesn't exceed NGX_HTTP_MAX_CAPTURES
    //although captures are not used for blocking
    if(n > NGX_HTTP_MAX_CAPTURES)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "[Content filter]: ngx_http_ct_filter_regex_compile "
                               "You want to capture too many regex substrings, "
                               "more than %i in \"%V\"",
                               n, &pair->match);
       return NGX_ERROR;
    }


#else
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "[Content filter]: ngx_http_ct_filter_regex_compile "
                       "the using of the regex \"%V\" requires PCRE library",
                       &pair->match);

    return NGX_ERROR;
#endif

    return NGX_OK;

}


static ngx_int_t
ngx_http_ct_match(ngx_http_request_t *r, ngx_http_ct_ctx_t *ctx)
{

    ngx_log_t   *log;
    ngx_int_t    count, match_count;
    #if (NGX_PCRE)
    ngx_buf_t   *src;
    ngx_uint_t   i;
    blk_pair_t  *pairs, *pair;
    ngx_str_t input;
    #endif

    match_count = 0;
    count = 0;

    log = r->connection->log;

    if(ngx_buf_size(ctx->line_in) <= 0)
    {
        return match_count;
    }


    #if (NGX_PCRE)
    src = ctx->line_in;

    if(!ctx->matched)
    {//this block will not run if sensitive content is already detected

        pairs = (blk_pair_t *) ctx->blk_pairs->elts;
        for (i = 0; i < ctx->blk_pairs->nelts; i++) {

            pair = &pairs[i];
            input.data = src->pos;
            input.len = ngx_buf_size(src);

            while(input.len > 0)
            {
                /* regex matching */

                pair->ncaptures = (NGX_HTTP_MAX_CAPTURES + 1) * 3;
                pair->captures = ngx_pcalloc(r->pool, pair->ncaptures * sizeof(int));

                count = ngx_regex_exec(pair->match_regex, &input, pair->captures, pair->ncaptures);
                if (count >= 0) {
                    /* Regex matches */
                    match_count += count;

                    /*
                      To track  previous matches pair->matched is used.
                    */
                    pair->matched++;

                    input.data = input.data + pair->captures[1];
                    input.len = input.len - pair->captures[1];

                    if(pair->matched >= pair->occurence)
                    {
                        ctx->matched++;
                        break;
                    }

                } else if (count == NGX_REGEX_NO_MATCHED) {
                     //no match break out of while loop
                     break;

                } else {

                    ngx_log_error(NGX_LOG_ERR, log, 0,  "[Content filter]: ngx_http_ct_match"
                                                        " regexec failed: %i", count);
                    goto failed;
                }

            }


            if(ctx->matched)
            {//one of the regex pair has matched
             //exit the for loop
              break;
            }


        }
    }
    #endif


    if (ngx_http_ct_out_chain_append(r, ctx,
        ctx->line_in)!= NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,  "[Content filter]: "
            "ngx_http_ct_match cannot append line to output buffer: %i", count);
            goto failed;
        }


    ngx_buffer_init(ctx->line_in);

    #if CONTF_DEBUG
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "[Content filter]: match counts: %i", match_count);
    #endif

    return match_count;

failed:

    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "[Content filter]: ngx_http_ct_match error.");

    return -1;
}


static ngx_int_t
ngx_http_ct_body_filter_process_buffer(ngx_http_request_t *r, ngx_buf_t *b)
{
    u_char               *p, *last, *linefeed;
    ngx_int_t             len, rc;
    ngx_http_ct_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ct_filter_module);

    if (b == NULL) {
        //Input buffer shouldn't be NULL
        //If it is NULL, it is an error
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[Content filter]: ngx_http_ct_body_filter_process_buffer "
            " input buffer is null");
        return NGX_ERROR;
    }

    p = b->pos;
    last = b->last;
    b->pos = b->last; //buffer is consumed

    #if CONTF_DEBUG
        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "[Content filter]: processing buffer: %p %uz, line_in buffer: %p %uz",
                       b, last - p,
                       ctx->line_in, ngx_buf_size(ctx->line_in));
    #endif

    if ((last - p) == 0 && ngx_buf_size(ctx->line_in) == 0){
        return NGX_OK;
    }

    if ((last - p) == 0 && ngx_buf_size(ctx->line_in) && ctx->last) {

        #if CONTF_DEBUG
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "[Content filter]: the last zero buffer, try to do substitution");
        #endif

        rc = ngx_http_ct_match(r, ctx);
        if (rc < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "[Content filter]: ngx_http_ct_body_filter_process_buffer"
                " regex matching for line fails");
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    while (p < last) {

        linefeed = memchr(p, LF, last - p);

        #if CONTF_DEBUG
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[Content filter]: find linefeed: %p",
                           linefeed);
        #endif

        if (linefeed == NULL) {

            if (ctx->last) {
              /* Last buffer no line feed. Set linefeed to last - 1 so
                it will be processed in subsequent block
                (last - 1) will unlikely be zero since last as a
                memory pointer should not be 1 unless there is an
                error elsewhere.  */
                linefeed = last - 1;

                #if CONTF_DEBUG
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "[Content filter]: the last buffer, not find linefeed");
                #endif
            }
            else {
                /* Not last buffer and no linefeed. Accumulate and wait for other buffers with linefeed*/
                if (buffer_append_string(ctx->line_in, p, last - p, r->pool)
                    == NULL) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "[Content filter]: ngx_http_ct_body_filter_process_buffer"
                        " cannot append to string buffer");
                    return NGX_ERROR;
                }

                break;
            }
        }

        if (linefeed) {

            len = linefeed - p + 1;

            if (buffer_append_string(ctx->line_in, p, len, r->pool) == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "[Content filter]: ngx_http_ct_body_filter_process_buffer  "
                        " cannot append to string buffer");
                return NGX_ERROR;
            }

            p += len;

            rc = ngx_http_ct_match(r, ctx);
            if (rc < 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     "[Content filter]: ngx_http_ct_body_filter_process_buffer"
                     " regex matching for line fails");
                return NGX_ERROR;
            }

        }
    }

    return NGX_OK;
}


/*
Check if the content encoding is compressed using either
gzip, deflate, compress or br (Brotli)
Returns true if compression is enabled,
false if it cannot determine compression
*/
static ngx_int_t
ngx_test_ct_compression(ngx_http_request_t *r)
{
    ngx_str_t tmp;

    if(r->headers_out.content_encoding == NULL)
    {//Cannot determine encoding, assume no compression
        return 0;
    }

    if(r->headers_out.content_encoding->value.len == 0 )
    {
        return 0;
    }

    tmp.len = r->headers_out.content_encoding->value.len;
    tmp.data = ngx_pcalloc(r->pool, sizeof(u_char) * tmp.len );

    if(tmp.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "[Content filter]: ngx_test_ct_compression "
            "cannot allocate buffer for compression check");
        return 0;
    }

    ngx_strlow(tmp.data,
               r->headers_out.content_encoding->value.data, tmp.len);



    if( tmp.len >= (sizeof("gzip") -1) &&
        ngx_strncmp(tmp.data, (u_char*)"gzip" , tmp.len) == 0 )
    {
        return 1;
    }

    if( tmp.len >= (sizeof("deflate") -1) &&
        ngx_strncmp(tmp.data, (u_char*)"deflate" , tmp.len) == 0 )
    {
        return 1;
    }

    if( tmp.len >= (sizeof("compress") -1) &&
        ngx_strncmp(tmp.data, (u_char*)"compress" , tmp.len) == 0 )
    {
        return 1;
    }


    if( tmp.len >= (sizeof("br") -1) &&
        ngx_strncmp(tmp.data, (u_char*)"br" , tmp.len) == 0 )
    {
        return 1;
    }

    if( tmp.len >= (sizeof("identity") -1) &&
        ngx_strncmp(tmp.data, (u_char*)"identity" , tmp.len) == 0 )
    {
        return 0;
    }


    //Fail safe to false if compression cannot be determined
    return 0;
}
