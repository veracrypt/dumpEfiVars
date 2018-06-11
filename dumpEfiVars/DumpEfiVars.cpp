/*
 * Copyright (c) 2018 Mounir IDRASSI <mounir.idrassi@idrix.fr>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of mosquitto nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <Windows.h>
#include "efi.h"

#include "openssl\x509.h"

#include <vector>
#include <string>
#include <stdio.h>
#include <strsafe.h>

typedef std::vector<unsigned char> ByteArray;

static std::wstring GetCertDetail(X509* x, int NID, bool bForIssuer = false)
{
    std::wstring szResult;
    X509_NAME* pName = (bForIssuer)? X509_get_issuer_name(x) : X509_get_subject_name(x);
    int lastpos = -1;
    lastpos = X509_NAME_get_index_by_NID(pName, NID, lastpos);
    if (lastpos != -1)
    {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(pName, lastpos);
        ASN1_STRING* pEntryStr = X509_NAME_ENTRY_get_data(e);

        BIO* b = BIO_new(BIO_s_mem());
        int status = ASN1_STRING_print_ex(b,pEntryStr,ASN1_STRFLGS_UTF8_CONVERT);
        if (status)
        {
            char szLine[1024];
			wchar_t szwVal[1024];
            while(BIO_gets(b, szLine, 1024))
            {
				MultiByteToWideChar (CP_UTF8, 0, szLine, -1, szwVal, ARRAYSIZE (szwVal));
                szResult += std::wstring(szwVal);
            }       
        }

        BIO_free(b);            
    }

    return szResult;
}

void Error (const wchar_t* szFn)
{
	wprintf (L"%s failed with error 0x%.8X\n", GetLastError());
}

BOOL SetPrivilege(LPCWSTR szName, BOOL bEnabled)
{
	HANDLE hToken;
	BOOL bStatus = FALSE;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		Error (L"OpenProcessToken");
	}
	else
	{
		TOKEN_PRIVILEGES tp;
		
		if(!LookupPrivilegeValue(NULL, szName, &tp.Privileges[0].Luid))
			Error (L"LookupPrivilegeValue");
		else
		{
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Attributes = bEnabled ? SE_PRIVILEGE_ENABLED : 0;
			if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
				bStatus = TRUE;
			else
				Error (L"AdjustTokenPrivileges");
		}
		CloseHandle (hToken);
	}
	
	return bStatus;
}

BOOL IsUefiBIOS ()
{
	BOOL bStatus = FALSE;
	if(!GetFirmwareEnvironmentVariable (L"", L"{00000000-0000-0000-0000-000000000000}", NULL, 0))
	{
		if (ERROR_INVALID_FUNCTION != GetLastError())
			bStatus = TRUE;
	}

	return bStatus;
}

bool ReadUefiVariable(LPCWSTR szName, ByteArray& value, const wchar_t* EfiVarGuid)
{
	bool bStatus = true;
	DWORD dwSize;
	value.resize (256);
	do
	{
		dwSize = GetFirmwareEnvironmentVariable (szName, EfiVarGuid, value.data(), (DWORD) value.size());
		if (dwSize || (GetLastError () != ERROR_INSUFFICIENT_BUFFER))
			break;
		else
		{
			value.resize(2 * value.size());
		}
	} while (value.size () <= (1024 *1024));

	if (bStatus)
		value.resize (dwSize);
	else
	{
		Error (L"GetFirmwareEnvironmentVariable");
		value.clear();
	}
	return bStatus;
}

void DumpBuffer (const wchar_t* name, const unsigned char* pbData, DWORD dwLen)
{
	DWORD dwBlockCount = 0, i;
	wprintf (L"%s (%d bytes): \n", name, (int) dwLen);
	while (dwLen)
	{
		wprintf (L"%.8X|", dwBlockCount++);
		for (i = 0; i < 16; i++)
		{
			if (i < dwLen)
				wprintf (L"%.2X", pbData[i]);
			else
				wprintf (L"__");
		}

		wprintf (L"|");

		for (i = 0; i < 16; i++)
		{
			unsigned char c = pbData[i];
			if ((i < dwLen) && (c >= 32) && (c <= 126))
				wprintf (L"%c", pbData[i]);
			else
				wprintf (L".");
		}

		wprintf (L"|\n");

		if (dwLen >= 16)
			dwLen -= 16;
		else
			dwLen = 0;

		pbData += 16;

	}
	wprintf (L"\n");
}

/* all the necessary guids */

EFI_GUID X509_GUID =   { 0xa5c059a1, 0x94e4, 0x4aa7, {0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72} };
EFI_GUID RSA2048_GUID = { 0x3c5766e8, 0x269c, 0x4e34, {0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6} };
EFI_GUID PKCS7_GUID = { 0x4aafd29d, 0x68df, 0x49ee, {0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7} };
EFI_GUID EFI_CERT_SHA256_GUID  = { 0xc1c41626, 0x504c, 0x4092, { 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28 } };

const wchar_t *guid_to_str(EFI_GUID *guid)
{
	static wchar_t str[256];

	StringCbPrintfW(str, sizeof (str), L"%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
		guid->Data1, guid->Data2, guid->Data3,
		guid->Data4[0], guid->Data4[1], guid->Data4[2],
		guid->Data4[3], guid->Data4[4], guid->Data4[5],
		guid->Data4[6], guid->Data4[7]);

	return str;
}


#define certlist_for_each_certentry(cl, cl_init, s, s_init)		\
	for (cl = (EFI_SIGNATURE_LIST *)(cl_init), s = (s_init);	\
		s > 0 && s >= cl->SignatureListSize;			\
		s -= cl->SignatureListSize,				\
		cl = (EFI_SIGNATURE_LIST *) ((UINT8 *)cl + cl->SignatureListSize))

/*
 * Warning: this assumes (cl)->SignatureHeaderSize is zero.  It is for all
 * the signatures we process (X509, RSA2048, SHA256)
 */
#define certentry_for_each_cert(c, cl)	\
  for (c = (EFI_SIGNATURE_DATA *)((UINT8 *) (cl) + sizeof(EFI_SIGNATURE_LIST) + (cl)->SignatureHeaderSize); \
	(UINT8 *)c < ((UINT8 *)(cl)) + (cl)->SignatureListSize; \
c = (EFI_SIGNATURE_DATA *)((UINT8 *)c + (cl)->SignatureSize))

void parse_db(const wchar_t *name, unsigned char *data, size_t len)
{
	EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)data;
	EFI_SIGNATURE_DATA  *Cert;
	long count = 0, DataSize = len;
	uint32 size;

	certlist_for_each_certentry(CertList, data, size, DataSize) {
		int Index = 0;
		const wchar_t *ext;

		if (memcmp(&CertList->SignatureType, &X509_GUID, sizeof (EFI_GUID))== 0) {
			ext = L"X509";
		} else if (memcmp(&CertList->SignatureType, &RSA2048_GUID, sizeof (EFI_GUID)) == 0) {
			ext = L"RSA2048";
		} else if (memcmp(&CertList->SignatureType, &PKCS7_GUID, sizeof (EFI_GUID)) == 0) {
			ext = L"PKCS7";
		} else if (memcmp(&CertList->SignatureType, &EFI_CERT_SHA256_GUID, sizeof (EFI_GUID)) == 0) {
			ext = L"SHA256";
		} else {
			ext = L"Unknown";
		}

		wprintf(L"%s: List %ld, type %s\n", name, count++, ext);

		certentry_for_each_cert(Cert, CertList) {
			const wchar_t* owner = guid_to_str(&Cert->SignatureOwner);

			wprintf(L"    Signature %d, size %d, owner %s\n",
			      Index++, CertList->SignatureSize,
			      owner);

			if (wcscmp(ext, L"X509") == 0) {
				const unsigned char *buf = (unsigned char *)Cert->SignatureData;
				X509 *X = d2i_X509(NULL, &buf,
						   CertList->SignatureSize);
				X509_NAME *issuer = X509_get_issuer_name(X);
				X509_NAME *subject = X509_get_subject_name(X);

				if (0 == wcscmp (name, L"db"))
				{
					std::wstring cn = GetCertDetail (X, NID_commonName);

					CreateDirectoryW (owner, NULL);
					std::wstring file = owner;
					file += L"\\";
					file += cn + L".der";

					FILE* f;
					if (0 == _wfopen_s (&f, file.c_str(), L"wb"))
					{
						fwrite (Cert->SignatureData,CertList->SignatureSize,1, f);
						fclose (f);
					}
				}
				
				wprintf(L"        Subject:\n");
				X509_NAME_print_ex_fp(stdout, subject, 12, XN_FLAG_SEP_CPLUS_SPC);
				wprintf(L"\n        Issuer:\n");
				X509_NAME_print_ex_fp(stdout, issuer, 12, XN_FLAG_SEP_CPLUS_SPC);
				wprintf(L"\n");

			} else if (wcscmp(ext, L"SHA256") == 0) {
				uint8 *hash = Cert->SignatureData;
				int j;

				wprintf(L"        Hash:");
				for (j = 0; j < 32; j++) {
					wprintf(L"%02x", hash[j]);
				}
				wprintf(L"\n");
			}
		}
	}
}

typedef struct _efiVarEntry
{
	const wchar_t* name;
	const wchar_t* guid;
} EfiVarEntry;

EfiVarEntry g_varsList[] = {
	{L"BootOrder", L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"},
	{L"BootCurrent", L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"},
	{L"BootNext", L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"},
	{L"SecureBoot", L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"},
	{L"Timeout", L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"},
	{L"PK",L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"},
	{L"KEK",L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"},
	{L"db",L"{d719b2cb-3d3a-4596-A3BC-DAD00E67656F}"},
	{L"dbx",L"{d719b2cb-3d3a-4596-A3BC-DAD00E67656F}"},
	{L"dbt", L"{d719b2cb-3d3a-4596-A3BC-DAD00E67656F}"},
	{L"MokList",L"{605dab50-e046-4300-abb6-3dd810dd8b23}"}
};

int wmain (int argc, wchar_t** argv)
{
	if (IsUefiBIOS())
	{
		if (SetPrivilege (SE_SYSTEM_ENVIRONMENT_NAME, TRUE))
		{
			ByteArray value;
			for (size_t i = 0; i< sizeof (g_varsList) / sizeof (EfiVarEntry); i++)
			{
				if (ReadUefiVariable (g_varsList[i].name, value, g_varsList[i].guid))
				{
					DumpBuffer (g_varsList[i].name, value.data(), (DWORD) value.size());
					if (0 == wcscmp (L"BootOrder", g_varsList[i].name))
					{
						unsigned short id;
						wchar_t name[16];
						ByteArray tmp;
						for (size_t j = 0; j < value.size() / 2; j++)
						{
							memcpy (&id, value.data() + (2*j), 2);
							StringCbPrintfW(name, sizeof(name), L"Boot%.4X", id);
							if (ReadUefiVariable (name, tmp, g_varsList[i].guid))
							{
								DumpBuffer (name, tmp.data(), (DWORD) tmp.size());
							}
						}
					}

					if (0 == wcscmp (L"db", g_varsList[i].name) 
						|| 0 == wcscmp (L"dbx", g_varsList[i].name)
						|| 0 == wcscmp (L"dbt", g_varsList[i].name)
						|| 0 == wcscmp (L"PK", g_varsList[i].name)
						|| 0 == wcscmp (L"KEK", g_varsList[i].name)
						)
					{
						parse_db (g_varsList[i].name, value.data(), value.size());
						if (value.size())
						{
							FILE* f;
							CreateDirectoryW (L"SigLists", NULL);
							std::wstring file =L"SigLists\\";
							file += g_varsList[i].name;
							file += L"_SigList.bin";
							if (0 == _wfopen_s (&f, file.c_str(), L"wb"))
							{
								fwrite (value.data(), 1, value.size(), f);
								fclose(f);
							}
						}
					}
				}
			}

			SetPrivilege (SE_SYSTEM_ENVIRONMENT_NAME, FALSE);
		}
	}
	else
		wprintf (L"UEFI not enabled on this machine.\n");

	wprintf (L"\n\nPress Enter to exit.");
	getchar ();

	return 0;
}
