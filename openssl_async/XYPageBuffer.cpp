#include "XYPageBuffer.h"
//---------------------------------------------------------------------------
// 函数功能: 构造内存块结构体
void InitializePageBuffer(PXYPAGE_BUFFER pb, unsigned char *buffer, unsigned int size, unsigned int pagesize)
{
	pb->buffer0 = buffer;
	pb->buffer1 = buffer;
	pb->size0 = size;
	pb->size1 = size;
	pb->offset = 0;

	pb->pagesize = pagesize;
}
// 函数功能: 释构内存块结构体
void UninitializePageBuffer( PXYPAGE_BUFFER pb)
{
	if (pb->buffer1 != pb->buffer0)				//两个指针不指向同一块内存
	{
		if (pb->buffer1 != NULL)				//指针不为空
		{
			FREE(pb->buffer1);
		}
	}
	// 
	pb->buffer1 = pb->buffer0;
	pb->size1 = pb->size0;
	pb->offset = 0;
}

// 函数功能: 往内存块结构体里面写入数据块
unsigned int WritePageBuffer(PXYPAGE_BUFFER pb, const unsigned char *buffer, unsigned int length)
{
	unsigned char *newbuffer;

	if (pb->offset + length > pb->size1)
	{
		pb->size1 = (pb->offset + length + pb->pagesize - 1) / pb->pagesize;
		pb->size1 *= pb->pagesize;
		newbuffer = (unsigned char *)MALLOC(pb->size1);
		if (newbuffer)
		{
			if (pb->offset > 0)
			{
				//psis->p_
				CopyMemory(newbuffer, pb->buffer1, pb->offset);
			}
		}
		if (pb->buffer1 != pb->buffer0)
		{
			FREE(pb->buffer1);
		}
		pb->buffer1 = newbuffer;
	}
	if (pb->buffer1)
	{
		if (buffer != NULL && length > 0)
		{
			CopyMemory(pb->buffer1 + pb->offset, buffer, length);
			pb->offset += length;
		}
	}
	else
	{
		pb->size1 = 0;

		length = 0;
	}

	return(length);
}
// 函数功能: 从内存块结构体里面读数据
unsigned int ReadPageBuffer(PXYPAGE_BUFFER pb, unsigned char *buffer, unsigned int length)
{
	if (length > pb->offset)
	{
		length = pb->offset;
	}
	if (length > 0)
	{
		if (buffer != NULL)
		{
			//psis->p_
			CopyMemory(buffer, pb->buffer1, length);
		}
		else
		{
			pb->offset -= length;
			if (pb->offset > 0)
			{
				//psis->p_
				MoveMemory(pb->buffer1, pb->buffer1 + length, pb->offset);
			}
		}
	}
	return(length);
}

// 函数功能: 减少内存块结构体所占的内存
unsigned char *ConvergencePageBuffer(PXYPAGE_BUFFER pb)
{
	unsigned char *buffer = NULL;
	unsigned int length;

	length = pb->offset;
	if (length > 0)
	{
		buffer = (unsigned char *)MALLOC(length);
		if (buffer != NULL)
		{
			CopyMemory(buffer, pb->buffer1, length);

			if (pb->buffer1 != pb->buffer0)
			{
				FREE( pb->buffer1);
			}
			pb->buffer1 = buffer;
		}
	}
	return(buffer);
}
//---------------------------------------------------------------------------