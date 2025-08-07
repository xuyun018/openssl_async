//---------------------------------------------------------------------------
// 内存块管理的基础类
//---------------------------------------------------------------------------
#ifndef XYPageBuffer_H
#define XYPageBuffer_H
//---------------------------------------------------------------------------
#include <windows.h>
//---------------------------------------------------------------------------
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
//---------------------------------------------------------------------------
typedef struct tagXYPAGE_BUFFER
{
	unsigned char *buffer0;
	unsigned char *buffer1;
	unsigned int size0;
	unsigned int size1;
	unsigned int offset;

	unsigned int pagesize;
}XYPAGE_BUFFER, *PXYPAGE_BUFFER;
//---------------------------------------------------------------------------
void InitializePageBuffer(PXYPAGE_BUFFER pb, unsigned char *buffer, unsigned int size, unsigned int pagesize);
void UninitializePageBuffer(PXYPAGE_BUFFER pb);

unsigned int WritePageBuffer(PXYPAGE_BUFFER pb, const unsigned char *buffer, unsigned int length);
// 需要读两次才能完成修改offset指针
unsigned int ReadPageBuffer(PXYPAGE_BUFFER pb, unsigned char *buffer, unsigned int length);
//---------------------------------------------------------------------------
#endif