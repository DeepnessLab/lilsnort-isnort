/* A Bison parser, made by GNU Bison 2.7.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2012 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_SFAT_TARGET_BASED_SF_ATTRIBUTE_TABLE_H_INCLUDED
# define YY_SFAT_TARGET_BASED_SF_ATTRIBUTE_TABLE_H_INCLUDED
/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int sfat_debug;
#endif

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     SF_AT_COMMENT = 258,
     SF_AT_WHITESPACE = 259,
     SF_START_SNORT_ATTRIBUTES = 260,
     SF_END_SNORT_ATTRIBUTES = 261,
     SF_AT_START_MAP_TABLE = 262,
     SF_AT_END_MAP_TABLE = 263,
     SF_AT_START_ENTRY = 264,
     SF_AT_END_ENTRY = 265,
     SF_AT_START_ENTRY_ID = 266,
     SF_AT_END_ENTRY_ID = 267,
     SF_AT_START_ENTRY_VALUE = 268,
     SF_AT_END_ENTRY_VALUE = 269,
     SF_AT_START_ATTRIBUTE_TABLE = 270,
     SF_AT_END_ATTRIBUTE_TABLE = 271,
     SF_AT_START_HOST = 272,
     SF_AT_END_HOST = 273,
     SF_AT_START_HOST_IP = 274,
     SF_AT_END_HOST_IP = 275,
     SF_AT_STRING = 276,
     SF_AT_NUMERIC = 277,
     SF_AT_IPv6 = 278,
     SF_AT_IPv6Cidr = 279,
     SF_AT_START_OS = 280,
     SF_AT_END_OS = 281,
     SF_AT_START_ATTRIBUTE_VALUE = 282,
     SF_AT_END_ATTRIBUTE_VALUE = 283,
     SF_AT_START_ATTRIBUTE_ID = 284,
     SF_AT_END_ATTRIBUTE_ID = 285,
     SF_AT_START_CONFIDENCE = 286,
     SF_AT_END_CONFIDENCE = 287,
     SF_AT_START_NAME = 288,
     SF_AT_END_NAME = 289,
     SF_AT_START_VENDOR = 290,
     SF_AT_END_VENDOR = 291,
     SF_AT_START_VERSION = 292,
     SF_AT_END_VERSION = 293,
     SF_AT_START_FRAG_POLICY = 294,
     SF_AT_END_FRAG_POLICY = 295,
     SF_AT_START_STREAM_POLICY = 296,
     SF_AT_END_STREAM_POLICY = 297,
     SF_AT_START_SERVICES = 298,
     SF_AT_END_SERVICES = 299,
     SF_AT_START_SERVICE = 300,
     SF_AT_END_SERVICE = 301,
     SF_AT_START_CLIENTS = 302,
     SF_AT_END_CLIENTS = 303,
     SF_AT_START_CLIENT = 304,
     SF_AT_END_CLIENT = 305,
     SF_AT_START_IPPROTO = 306,
     SF_AT_END_IPPROTO = 307,
     SF_AT_START_PORT = 308,
     SF_AT_END_PORT = 309,
     SF_AT_START_PROTOCOL = 310,
     SF_AT_END_PROTOCOL = 311,
     SF_AT_START_APPLICATION = 312,
     SF_AT_END_APPLICATION = 313
   };
#endif


#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{
/* Line 2058 of yacc.c  */
#line 62 "../../target-based/sf_attribute_table.y"

  char stringValue[STD_BUF];
  uint32_t numericValue;
  AttributeData data;
  MapData mapEntry;


/* Line 2058 of yacc.c  */
#line 123 "../../target-based/sf_attribute_table.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE sfat_lval;

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int sfat_parse (void *YYPARSE_PARAM);
#else
int sfat_parse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int sfat_parse (void);
#else
int sfat_parse ();
#endif
#endif /* ! YYPARSE_PARAM */

#endif /* !YY_SFAT_TARGET_BASED_SF_ATTRIBUTE_TABLE_H_INCLUDED  */
