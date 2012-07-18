#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

struct _tag;
struct _attr;

typedef struct {
	SV *name;
	SV *value;
} attr;

typedef struct {
	SV          *name;
	AV          *attrs;
	struct _tag *children;
	char        *value;
} tag;

typedef enum {
		START,
		XMLDEC,
		XMLDEC_NAME,
		XMLDEC_END,
		XMLDEC_END2,
		ATTR_NONE,
		ATTR_NAME,
		ATTR_EQ,
		ATTR_VALUE,
		ATTR_VALUE_CAPTURE,
		NONE,
		LT_OPEN,
		PI,
		COMMENT_MAYBE,
		COMMENT,
		CDATA,
		TAG_OPEN,
		TAG_OPEN_END,
		TAG_OPEN_END_CLOSE,
		TAG_ATTRS,
		TAG_CLOSE,
		TAG_CLOSE_END
} state;

const char* state_name[] = {
		"START",
		"XMLDEC",
		"XMLDEC_NAME",
		"XMLDEC_END",
		"XMLDEC_END2",
		"ATTR_NONE",
		"ATTR_NAME",
		"ATTR_EQ",
		"ATTR_VALUE",
		"ATTR_VALUE_CAPTURE",
		"NONE",
		"LT_OPEN",
		"PI",
		"COMMENT_MAYBE",
		"COMMENT",
		"CDATA",
		"TAG_OPEN",
		"TAG_OPEN_END",
		"TAG_OPEN_END_CLOSE",
		"TAG_ATTRS",
		"TAG_CLOSE",
		"TAG_CLOSE_END"
};

typedef enum {
	SYNTAX_ERROR,
	RESTRICTION
} error;

typedef struct {
	int   len;
	char *str;
} lstring;

typedef struct {
	state state;
	
	int   size;
	
	int   depth;
	
	unsigned char *tag_name;
	int            tag_name_len;
	int            tag_len;
	
	unsigned char *stanza_begin;
	
	
	int             buf_size;
	unsigned char * buf;
	unsigned char * ptr;
	unsigned char * last;
	
	int       stack_size;
	lstring  *stack;
	
	state return_to;
	
	unsigned char attr_char;
	char          allow_comments;
	char          received_declaration;
	char          closing;
	
	void (*error)( void *, error, char *, ... );
	void (*stream_open) ( void *, char *, int, char *, int );
	void (*stanza)      ( void *, char *, int, char *, int );
	void (*stream_close)( void *, char *, int, char *, int );
	
	void  *ctx; // user defined pointer
} StreamXML;

const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789";


#define case_wsp   \
		case 0xa  :\
		case 0x9  :\
		case 0xd  :\
		case 0x20

#define TRACE 0

void sxml_collapse(StreamXML * s) {
	if (s->last == s->buf) return;
	int i;
	int freed = s->last - s->buf;
	//warn("rewind on %d (%p -> %p -> %p)", freed, s->buf, s->last, s->ptr);
	//warn("before rewind: %d [%s]",s->size, s->buf);
	s->size         -= freed;
	s->ptr          -= freed;
	s->tag_name     -= freed;
	s->stanza_begin -= freed;
#if TRACE
	warn("memmove %p -> %p (%d)",s->buf, s->last, s->size);
#endif
	memmove(s->buf, s->last, s->size);
	for(i=1;i<s->depth;i++) {
		s->stack[i].str -= freed;
		//warn("stack %d: %-.*s\n",i,s->stack[i].len,s->stack[i].str);
	}
	s->last = s->buf;
	s->buf[s->size] = 0;
#if TRACE
	memset(s->buf + s->size, 'a', s->buf_size - s->size);
	warn("after rewind: Size:%d; [%-.*s] (%p -> %p)",s->size, s->size, s->buf, s->buf, s->ptr);
	warn("XXX(%d)[%s]", s->buf_size - s->size, s->buf);
#endif
	
	return;
/*
*/
}

void sxml_tag_open(StreamXML * s) {
	if ( strncmp( s->tag_name, "stream:stream", s->tag_name_len ) == 0 ) {
		s->depth = 0;
	}
	if (s->depth == 0) {
		s->stream_open( s, s->tag_name - 1, s->tag_len+2, s->tag_name, s->tag_name_len );
		s->last = s->tag_name + s->tag_len + 1;
	}
	else
	if (s->depth == 1) {
		s->stanza_begin = s->tag_name - 1;
	}
	if (s->depth + 2 > s->stack_size) {
		s->error(s, RESTRICTION, "Nesting too deep" );
		return;
	}
	if (s->depth == 0) {
		if (s->buf_size - s->size < s->tag_name_len) {
			s->error(s, RESTRICTION, "Buffer too small to store root node name" );
			return;
		}
		s->buf_size -= s->tag_name_len;
		memcpy(s->buf + s->buf_size, s->tag_name, s->tag_name_len);
		s->tag_name = s->buf + s->buf_size;
#if TRACE
		warn("Lower buf size on %d, name: %p (%-.*s) ", s->tag_name_len, s->tag_name,s->tag_name_len,s->tag_name);
		warn("XXX(%d)[%s]", s->buf_size - s->size, s->buf);
#endif
	}
	//warn("Put to stack at depth %d %-.*s",s->depth,s->tag_name_len, s->tag_name);
	s->stack[s->depth].len = s->tag_name_len;
	s->stack[s->depth].str = s->tag_name;
	s->depth++;
	
}

void sxml_tag_nochild(StreamXML * s) {
	if (s->depth == 1) {
		s->stanza( s, s->tag_name - 1, s->tag_len + 2, s->tag_name, s->tag_name_len );
		s->last = s->tag_name + s->tag_len + 1;
		
	}
}

void sxml_tag_close(StreamXML * s) {
	if (s->depth == 0) {
		s->error(s, SYNTAX_ERROR, "Close tag on level 0" );
		return;
	}
	if ( strncmp( s->stack[ s->depth - 1 ].str, s->tag_name, s->tag_name_len ) == 0 ) {
		s->depth--;
		if (s->depth == 1) {
			s->stanza( s, s->stanza_begin, s->tag_name + s->tag_len + 1 - s->stanza_begin, s->tag_name, s->tag_name_len );
			s->last = s->tag_name + s->tag_len + 1;
		}
		else
		if (s->depth == 0) {
			s->buf_size += s->stack[0].len;
			s->stream_close( s, s->tag_name - 2, s->tag_len + 3, s->tag_name, s->tag_name_len );
			s->last = s->tag_name + s->tag_len + 1;
		}
	} else {
		s->error(s, SYNTAX_ERROR, "Close mismatch. Need [%-.*s], got [%-.*s]", s->stack[ s->depth - 1 ].len, s->stack[ s->depth - 1 ].str, s->tag_len, s->tag_name );
		return;
	}
}

void sxml_declaration(StreamXML * s) {
	//printf("declaration [%-.*s]\n",s->tag_name_len, s->tag_name);
}



void sxml_drain(StreamXML * s) {
	unsigned char *p;
#if TRACE
	printf("Call drain (size: %d) %p -> %p (%-.10s...)\n", s->size, s->ptr, s->buf + s->size, s->ptr);
#endif
	for ( p = s->ptr; p < s->buf + s->size; p++ ) {
#if TRACE
		printf("S:%s; D:%d; P: %d [%02x]; buf=[%d][%-.*s] + [%-.*s]\n", state_name[s->state], s->depth, p - s->buf, *p, s->buf_size, s->size + ( s->buf - p ), p,
			s->depth ? s->stack[0].len : 4,
			s->depth ? s->stack[0].str : "none"
		);
#endif
		switch(s->state) {
			case START:
				switch(*p) {
					case_wsp:
						break;
					case '<':
						s->state = XMLDEC;
						break;
					default:
						s->error(s,SYNTAX_ERROR, "Waiting for <, received %c", *p);
						return;
				}
				break;
			/*
			case XMLDEC:
				expect("?xml");pos++;
				return_to = State.XMLDEC_END;
				state = State.TAG_ATTRS;
				break;
			*/
			case NONE:
				switch(*p) {
					case_wsp: break;
					case '<':
						s->state = LT_OPEN;
						break;
					default:
						if (s->depth > 1) {
							break;
						} else {
							s->error(s,SYNTAX_ERROR, "Non-whitespace at zero depth: 0x%02x (%c)",*p,*p == 0 ? ' ' : *p);
							return;
						}
				}
				break;
			case LT_OPEN:
				switch(*p) {
					case '!':
						s->state = PI;
						break;
					case '/':
						s->tag_name = p + 1;
						s->state = TAG_CLOSE;
						break;
					case '?':
						s->state = XMLDEC_NAME;
						s->tag_name = p + 1;
						break;
					default:
						s->tag_name = p;
						s->state = TAG_OPEN;
						break;
					}
					break;
			case PI:
					switch(*p) {
						case '-':
							s->state = COMMENT_MAYBE;
							break;
						case '[':
							if ( p - s->buf > s->size - 7 ) {
								p--;
								warn("Need more data for CDATA DETECTION");
								//s->ptr = p;
								return;
							}
							if (strncmp(p,"[CDATA[",7) != 0) {
								s->error(s,SYNTAX_ERROR, "Only CDATA supported, got: %s", p);
								return;
							}
							p = s->ptr = p + 7;
							s->state = CDATA;
							if (s->depth < 2) {
								s->error(s,SYNTAX_ERROR, "CDATA is restricted on levels < 2");
								return;
							}
							break;
						default:
							s->error(s,SYNTAX_ERROR, "Processing instructions not supported (%s)", p);
							return;
					}
					break;
			case COMMENT_MAYBE:
					switch(*p) {
						case '-':
							if (s->allow_comments) {
								s->state = COMMENT;
								break;
							} else {
								s->error(s,SYNTAX_ERROR, "Comments nodes are restricted");
								return;
							}
						default:
							s->error(s,SYNTAX_ERROR, "Processing instructions not supported");
							return;
					}
					//break;
			case COMMENT:
					switch(*p) {
						case '-':
							s->closing++;
							break;
						case '>':
							if (s->closing > 1) {
								s->state = NONE;
								break;
							}
							// no break
						default :
							s->closing = 0;
					}
					break;
			case CDATA:
					switch(*p) {
						case ']':
							s->closing++;
							break;
						case '>':
							if (s->closing > 1) {
								// attrValue[1] = pos - attrValue[0] - 2; // not reqired
								//System.out.printf("CDATA[%s]\n", new String(buf, attrValue[0], attrValue[1]));
								s->state = NONE;
								break;
							}
							// no break
						default :
							s->closing = 0;
					}
					break;

			case XMLDEC_NAME:
					switch(*p) {
						case_wsp:
							s->tag_name_len = p - s->tag_name;
							s->return_to = XMLDEC_END;
							s->state = TAG_ATTRS;
							break;
						case '?':
							s->tag_name_len = p - s->tag_name;
							s->state = XMLDEC_END2;
							break;
						default:
							if( strchr(chars, *p) ) {
								break;
							} else {
								s->error(s, SYNTAX_ERROR, "Bad symbol: %c", *p);
								return;
							}
					}
					break;
			case XMLDEC_END:
					switch(*p) {
						case '?':
							s->state = XMLDEC_END2;
							break;
						default:
							s->error(s, SYNTAX_ERROR, "Declaration expected: %c", *p); //XMLExceptionDeclarationExpected
							return;
					}
					break;
			case XMLDEC_END2:
					switch(*p) {
						case '>':
							sxml_declaration(s);
							if (strncasecmp( s->tag_name, "xml", s->tag_name_len ) == 0 ) {
								s->state = NONE;
								s->depth = 0;
								s->received_declaration = 1;
								break;
							}
							else {
								if (s->received_declaration) {
									s->error(s, SYNTAX_ERROR, "Restricted processing instruction %-.*s", s->tag_name_len, s->tag_name);
									return;
								} else {
									s->error(s, SYNTAX_ERROR, "Expected XML declaration, received %-.*s", s->tag_name_len, s->tag_name);
									return;
								}
							}
						default:
							s->error(s, SYNTAX_ERROR, "Declaration end expected: %c", *p); //XMLExceptionDeclarationExpected
							return;
					}
					break;
			case TAG_OPEN:
					switch(*p) {
						case_wsp:
							s->tag_name_len = p - s->tag_name;
							s->return_to = TAG_OPEN_END;
							s->state = TAG_ATTRS;
							break;
						case '>':
						case '/':
							s->tag_name_len = p - s->tag_name;
							p--;
							s->state = TAG_OPEN_END;
							break;
						default:
							break;
//							if( "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-:".indexOf(buf[pos]) > -1 ) {
//								break;
//							} else {
//								throw new XMLExceptionDeclarationExpected();
//							}
					}
					break;
			case TAG_OPEN_END:
					switch(*p) {
						case '/':
							s->state = TAG_OPEN_END_CLOSE;
							break;
						case '>':
							s->tag_len = p - s->tag_name;
							sxml_tag_open(s);
							s->state = NONE;
							break;
						default:
							s->error(s, SYNTAX_ERROR, "Waiting for > or /, received %c", *p);
							return;
					}
					break;
			case TAG_OPEN_END_CLOSE:
					switch(*p) {
						case '>':
							s->tag_len = p - s->tag_name;
							sxml_tag_nochild(s);
							s->state = NONE;
							break;
						default:
							s->error(s, SYNTAX_ERROR, "Waiting for >, received %c", *p);
							return;
					}
					break;
			case TAG_CLOSE:
					switch(*p) {
						case_wsp:
							s->tag_name_len = p - s->tag_name;
							if (s->tag_name_len < 1) {
								s->error(s, SYNTAX_ERROR, "Empty tag name (%-.10s -> %-.10s)",s->tag_name,p);
								return;
							}
							s->state = TAG_CLOSE_END;
							break;
						case '>':
							s->tag_len =
							s->tag_name_len = p - s->tag_name;
							sxml_tag_close(s);
							s->state = NONE;
							break;
						default:
							break;
					}
					break;
			case TAG_CLOSE_END:
					switch(*p) {
						case_wsp:
							break;
						case '>':
							s->tag_len = p - s->tag_name;
							sxml_tag_close(s);
							s->state = NONE;
							break;
						default:
							s->error(s, SYNTAX_ERROR, "Expected whitespace or >, received %c",*p);
							return;
					}
					break;
			case TAG_ATTRS:
					switch(*p) {
						case_wsp:
							break;
						case '/':
						case '>':
							if (s->return_to == TAG_OPEN_END) {
								p--;
								s->state = s->return_to;
								break;
							} else {
								s->error(s, SYNTAX_ERROR, "Bad return to on '>' for TAG_ATTRS");
								return;
							}
						case '?':
							if (s->return_to == XMLDEC_END) {
								p--;
								s->state = s->return_to;
								break;
							} else {
								s->error(s, SYNTAX_ERROR, "Bad return to on '?' for TAG_ATTRS");
								return;
							}
						default:
							// attrName[0] = pos; // not reqired
							s->state = ATTR_NAME;
					}
					break;
			case ATTR_NAME:
					switch(*p) {
						case_wsp:
							// attrName[1] = pos - attrName[0]; // not reqired
							s->state = ATTR_EQ;
							break;
						case '=':
							// attrName[1] = pos - attrName[0]; // not reqired
							s->state = ATTR_VALUE;
							break;
						case '/':
						case '>':
						case '?':
							s->error(s, SYNTAX_ERROR, "Bad termination for ATTR_NAME: %0.5s...", p);
							return;
						default:
							break;
					}
					break;
				case ATTR_EQ:
					switch(*p) {
						case_wsp:
							break;
						case '=':
							s->state = ATTR_VALUE;
							break;
						default:
							s->error(s, SYNTAX_ERROR, "Waiting for = after attribute name, received %c",*p);
							return;
					}
					break;
				case ATTR_VALUE:
					switch(*p) {
						case_wsp:
							break;
						case '\'':
						case '"':
							s->attr_char = *p;
							s->state = ATTR_VALUE_CAPTURE;
							// attrValue[0] = pos+1; // not reqired
							break;
						default:
							s->error(s, SYNTAX_ERROR, "Waiting for ' or \" after attribute =, received %c",*p);
							return;
					}
					break;
				case ATTR_VALUE_CAPTURE:
					switch(*p) {
						case '\'':
						case '"':
							if (*p == s->attr_char) {
								// attrValue[1] = pos - attrValue[0]; // not reqired
								/*
								System.out.printf("Captured attr: %s=%s\n",
									new String(buf, attrName[0],  attrName[1]),
									new String(buf, attrValue[0], attrValue[1])
								);
								*/
								s->state = TAG_ATTRS;
							}
							break;
						case '<':
							s->error(s, SYNTAX_ERROR, "Unescaped '<' not allowed in attributes values");
							return;
						default:
							break;
					}
					break;
			
			default:
				warn("Falled to state %d\n",s->state);
				s->error(s,0,"Unprocessed state: %s",state_name[s->state]);
				//s->ptr = p;
				return;
		}
	}
	s->ptr = p;
	sxml_collapse(s);
}

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

void on_error( void * ptr, error error, char * fmt, ... ) {
	StreamXML * s = (StreamXML *) ptr;
	char buf[256];
	va_list ap;
	va_start(ap, fmt);
	(void) vsnprintf(buf, 256, fmt, ap);
	va_end(ap);
	croak("Error: %d (%s)", error, buf);
}

typedef struct {
	SV * cb_open;
	SV * cb_read;
	SV * cb_close;
} plctx;

void on_stanza( void * ptr, char * begin, int len, char *name, int nlen ) {
	dSP;
	StreamXML * s = (StreamXML *) ptr;
	plctx     * ctx = (plctx *) s->ctx;
	if (!ctx->cb_read) return;
	
	ENTER;
	SAVETMPS;
	
	PUSHMARK (SP);
	EXTEND(SP,2);
	PUSHs( sv_2mortal(newSVpvn(name,nlen)) );
	PUSHs( sv_2mortal(newSVpvn(begin,len)) );
	PUTBACK;
	
	call_sv( ctx->cb_read, G_DISCARD | G_VOID );

	FREETMPS;
	LEAVE;
	
}

void on_stream_open( void * ptr, char * begin, int len, char *name, int nlen ) {
	dSP;
	StreamXML * s = (StreamXML *) ptr;
	plctx     * ctx = (plctx *) s->ctx;
	if (!ctx->cb_open) return;
	
	ENTER;
	SAVETMPS;
	
	PUSHMARK (SP);
	EXTEND(SP,2);
	PUSHs( sv_2mortal(newSVpvn(name,nlen)) );
	PUSHs( sv_2mortal(newSVpvn(begin,len)) );
	PUTBACK;
	
	call_sv( ctx->cb_open, G_DISCARD | G_VOID );

	FREETMPS;
	LEAVE;
}

void on_stream_close( void * ptr, char * begin, int len, char *name, int nlen ) {
	dSP;
	StreamXML * s = (StreamXML *) ptr;
	plctx     * ctx = (plctx *) s->ctx;
	if (!ctx->cb_close) return;
	
	ENTER;
	SAVETMPS;
	
	PUSHMARK (SP);
	EXTEND(SP,2);
	PUSHs( sv_2mortal(newSVpvn(name,nlen)) );
	PUSHs( sv_2mortal(newSVpvn(begin,len)) );
	PUTBACK;
	
	call_sv( ctx->cb_close, G_DISCARD | G_VOID );

	FREETMPS;
	LEAVE;
}


MODULE = XML::Fast::Stream		PACKAGE = XML::Fast::Stream		

SV *
new(SV *pk, HV * conf)
CODE:
	HV *stash = gv_stashpv(SvPV_nolen(pk), TRUE);
	plctx * ctx = safemalloc( sizeof(plctx) );
	if (!ctx) croak("Can't allocate context");
	memset(ctx,0,sizeof(plctx));
	StreamXML * s = safemalloc( sizeof(StreamXML) );
	if (!s) croak("Can't allocate parser");
	memset(s,0,sizeof(StreamXML));
	
	s->buf_size = 4096; // from param
	
	SV **key;
	if ((key = hv_fetch(conf, "open", 4, 0)) && SvROK(*key)) {
		ctx->cb_open = *key;
		SvREFCNT_inc(ctx->cb_open);
	}
	if ((key = hv_fetch(conf, "close", 5, 0)) && SvROK(*key)) {
		ctx->cb_close = *key;
		SvREFCNT_inc(ctx->cb_close);
	}
	if ((key = hv_fetch(conf, "read", 4, 0)) && SvROK(*key)) {
		ctx->cb_read = *key;
		SvREFCNT_inc(ctx->cb_read);
	}
	if ((key = hv_fetch(conf, "buffer", 6, 0)) && SvIOK(*key)) {
		s->buf_size = SvIV(*key);
	}
	
	s->state = NONE;
	s->allow_comments = 1; // from param
	s->last = s->ptr = s->buf = safemalloc( s->buf_size );
	if (!s->buf) croak("Can't allocate buffer");
	//memset(s->buf, 'x', s->buf_size ); s->buf[s->buf_size] = 0;
	//warn("Created parser. buf=%p, last=%p", s->buf, s->last);
	s->error        = on_error;
	s->stanza       = on_stanza;
	s->stream_open  = on_stream_open;
	s->stream_close = on_stream_close;
	s->stack_size = 256; // from param
	

	
	s->ctx = (void *)ctx;
	s->stack = safemalloc( sizeof(lstring) * s->stack_size );
	if (!s->stack) croak("Can't allocate stack");
	memset(s->stack,0, sizeof(lstring) * s->stack_size );
	
	ST(0) = sv_2mortal (sv_bless (newRV_noinc (newSViv(PTR2IV( s ))), stash));
	XSRETURN(1);

void
parse(SV *self, SV *svbuf)
CODE:
	StreamXML * s = ( StreamXML * ) SvUV( SvRV( self ) );
	STRLEN len, part;
#if TRACE
	warn("parse(%s)",SvPV_nolen(svbuf));
#endif
	char *buf = SvPV( svbuf,len );
	char *end;
	if (s->buf_size - s->size < len) {
		end = buf + len;
		while ( ( ( part = s->buf_size - s->size ) > 0 ) && buf < end ) {
			if (part > end - buf) part = end - buf;
			//warn("Copy part of size %d: [%-.*s]", part, part,buf);
			memcpy( s->buf + s->size, buf, part );
			//printf("Buffer = [%s]\n",s->buf);
			s->size += part;
			//s->buf[s->size] = 0;
#if TRACE
			printf("Received (%d) [%-.*s]. Now at: [%c][%s] (%p -> %d -> %p)\n", part, part, buf, *s->ptr, s->ptr, s->buf, s->size, s->ptr);
#endif
			
			buf += part;
			
			sxml_drain(s);
			
			//croak("TODO: %d", s->buf_size - s->size);
			
		}
		if (buf == end) {
		}
		else {
			croak("Buffer too small (%d). Need: +%d, Current (%d): %-.100s...", s->buf_size, end - buf, s->size, s->buf);
		}
	} else {
		memcpy( s->buf + s->size, buf, len );
		s->size += len;
		s->buf[s->size] = 0;
#if TRACE
		printf("Received (%d) [%-.*s]. Now at: [%c][%s] (%p -> %d -> %p)\n", len, len, buf, *s->ptr, s->ptr, s->buf, s->size, s->ptr);
#endif
		SvREFCNT_inc(self);
		sxml_drain(s);
		SvREFCNT_dec(self);
	}

void
DESTROY(SV *self)
CODE:
	StreamXML * s = ( StreamXML * ) SvUV( SvRV( self ) );
	plctx *ctx = (plctx *) s->ctx;
	if (ctx->cb_open) { SvREFCNT_dec(ctx->cb_open); }
	if (ctx->cb_read) { SvREFCNT_dec(ctx->cb_read); }
	if (ctx->cb_close){ SvREFCNT_dec(ctx->cb_close); }
	safefree(s->buf);
	safefree(s->stack);
	safefree(s->ctx);
	safefree(s);
	//warn("Destroyed parser");








