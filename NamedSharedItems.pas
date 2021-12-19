{-------------------------------------------------------------------------------

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.

-------------------------------------------------------------------------------}
{===============================================================================

  Shared named items

    Provides a class (TNamedSharedItem) to be used for small named shared
    (system-wide) memory blocks (here named items).

    It is inteded only for shared objects or medium-size data (at most 1KiB,
    this limit is enforced), but since each item has significant overhead
    (32 bytes at minimum), it should not be used for simple shared variables.
    Items are not allowed to have size of zero.

    The size of the item is kind-of domain separation - items with equal size
    are "living" in the same space, and items with differing sizes are kept
    completely separate.
    So two items with the same name but differing sizes are distinct. Two items
    with equal size but differing name are also distinct. But two items with
    equal both size and name will point to the same shared memory.
    Given the implementation, do not use this to create many items with
    differing sizes, as each size-space has somewhat high overhead (200+KiB).

    The items are in fact not discerned by their full name, they are discerned
    by a cryptographic hash (SHA1) of their name. So there is a very small, but
    still non-zero, posibility of name conflicts. Be aware of that.
    
    Length of the item name is not explicitly limited.

  Version 1.0 alpha (2021-12-18) - needs serious testing

  Last change 2021-12-18

  ©2021-2022 František Milt

  Contacts:
    František Milt: frantisek.milt@gmail.com

  Support:
    If you find this code useful, please consider supporting its author(s) by
    making a small donation using the following link(s):

      https://www.paypal.me/FMilt

  Changelog:
    For detailed changelog and history please refer to this git repository:

      github.com/TheLazyTomcat/Lib.NamedSharedItems

  Dependencies:
    AuxTypes           - github.com/TheLazyTomcat/Lib.AuxTypes
    AuxClasses         - github.com/TheLazyTomcat/Lib.AuxClasses
    SHA1               - github.com/TheLazyTomcat/Lib.SHA1
    SharedMemoryStream - github.com/TheLazyTomcat/Lib.SharedMemoryStream
    StrRect            - github.com/TheLazyTomcat/Lib.StrRect
    BitOps             - github.com/TheLazyTomcat/Lib.BitOps
    HashBase           - github.com/TheLazyTomcat/Lib.HashBase
    StaticMemoryStream - github.com/TheLazyTomcat/Lib.StaticMemoryStream
  * SimpleCPUID        - github.com/TheLazyTomcat/Lib.SimpleCPUID
  * InterlockedOps     - github.com/TheLazyTomcat/Lib.InterlockedOps
  * SimpleFutex        - github.com/TheLazyTomcat/Lib.SimpleFutex

  Libraries SimpleFutex and InterlockedOps are required only when compiling for
  Linux operating system.

  SimpleCPUID might not be required, depending on defined symbols in libraries
  InterlockedOps and BitOps.

===============================================================================}
unit NamedSharedItems;

{$IFDEF FPC}
  {$MODE ObjFPC}
{$ENDIF}
{$H+}

interface

uses
  SysUtils,
  AuxTypes, AuxClasses, SHA1, SharedMemoryStream;

{===============================================================================
    Library-specific exception
===============================================================================}
type
  ENSIException = class(Exception);

  ENSIInvalidValue        = class(ENSIException);
  ENSIOutOfResources      = class(ENSIException);
  ENSIItemAllocationError = class(ENSIException);

{===============================================================================
--------------------------------------------------------------------------------
                                TNamedSharedItem
--------------------------------------------------------------------------------
===============================================================================}
{===============================================================================
    TNamedSharedItem - class declaration
===============================================================================}
type
  TNamedSharedItem = class(TCustomObject)
  protected
    fName:              String;
    fNameHash:          TSHA1;
    fSize:              TMemSize;
    fInfoSection:       TSharedMemory;
    fDataSectionIndex:  Integer;
    fDataSection:       TSimpleSharedMemory;  // no locking (to save some resources)
    fItemMemory:        Pointer;
    fPayloadMemory:     Pointer;
    // some helper fields
    fFullItemSize:      TMemSize;
    fItemsPerSection:   UInt32;
    Function GetInfoSectionName: String; virtual;
    Function GetDataSectionName(Index: Integer): String; virtual;
    procedure FindOrAllocateItem; virtual;
    procedure AllocateItem; virtual;
    procedure DeallocateItem; virtual;
    procedure Initialize(const Name: String; Size: TMemSize); virtual;
    procedure Finalize; virtual;
  public
    constructor Create(const Name: String; Size: TMemSize);
    destructor Destroy; override;
    property Name: String read fName;
    property Size: TMemSize read fSize;
    property Memory: Pointer read fPayloadMemory;
  end;

implementation

uses
  StrRect, BitOps;

{===============================================================================
--------------------------------------------------------------------------------
                                TNamedSharedItem
--------------------------------------------------------------------------------
===============================================================================}
{-------------------------------------------------------------------------------
    TNamedSharedItem - info section types and constants
-------------------------------------------------------------------------------}
const
  NSI_SHAREDMEMORY_INFOSECT_MAXCOUNT = 16 * 1024; // total 1GiB of memory with 64KiB data sections

type
  TNSIDataSectionInfo = packed record
    ItemCount:  UInt32; // number of taken item slots within this data section
    Flags:      UInt32; // unused atm
  end;

  TNSIDataSectionsArray = packed array[0..Pred(NSI_SHAREDMEMORY_INFOSECT_MAXCOUNT)] of TNSIDataSectionInfo;

  TNSIInfoSection = packed record
    Flags:        UInt32;
    Reserved:     array[0..27] of Byte;
    DataSections: TNSIDataSectionsArray;
  end;
  PNSIInfoSection = ^TNSIInfoSection;

const
  NSI_SHAREDMEMORY_INFOSECT_NAME = 'nsi_section_%d_info';  // size
  NSI_SHAREDMEMORY_INFOSECT_SIZE = SizeOf(TNSIInfoSection);

  NSI_INFOSECT_FLAG_ACTIVE = UInt32($00000001);

{-------------------------------------------------------------------------------
    TNamedSharedItem - data section types and constants
-------------------------------------------------------------------------------}
type
  TNSIItemPayload = record end; // zero-size placeholder

  TNSIItemHeader = packed record
    RefCount: UInt32;               // reference counter
    Flags:    UInt32;               // currently unused
    Hash:     TSHA1;                // 20 bytes
    Reserved: array[0..3] of Byte;  // right now only alignment padding
    Payload:  TNSIItemPayload       // aligned to 32-byte boundary
  end;
  PNSIItemHeader = ^TNSIItemHeader;

const
  NSI_SHAREDMEMORY_DATASECT_ALIGNMENT   = 32;                   // 256 bits
  NSI_SHAREDMEMORY_DATASECT_MAXITEMSIZE = 1024;                 // 1KiB
  NSI_SHAREDMEMORY_DATASECT_SIZE        = 64 * 1024;            // 64KiB
  NSI_SHAREDMEMORY_DATASECT_NAME        = 'nsi_section_%d_%d';  // size, index

{===============================================================================
    TNamedSharedItem - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TNamedSharedItem - protected methods
-------------------------------------------------------------------------------}

Function TNamedSharedItem.GetInfoSectionName: String;
begin
Result := Format(NSI_SHAREDMEMORY_INFOSECT_NAME,[fSize])
end;

//------------------------------------------------------------------------------

Function TNamedSharedItem.GetDataSectionName(Index: Integer): String;
begin
Result := Format(NSI_SHAREDMEMORY_DATASECT_NAME,[fSize,Index])
end;

//------------------------------------------------------------------------------

procedure TNamedSharedItem.FindOrAllocateItem;
var
  InfoSectionPtr:       PNSIInfoSection;
  i,j:                  Integer;
  SectionFirstUnused:   Integer;
  SectionFirstFreeSlot: Integer;
  ProbedSection:        TSimpleSharedMemory;
  ProbedItem:           PNSIItemHeader;
begin
// info section should be already locked and prepared by this point
InfoSectionPtr := PNSIInfoSection(fInfoSection.Memory);
SectionFirstUnused := -1;
SectionFirstFreeSlot := -1;
{
  Traverse all sections and, in those containing at least one item, search for
  occurence of item with the same hash as has this item. Along the way, look
  for empty slots and unused sections.

  Since all data sections are traversed, if the item is not found, there should
  be at least one section unused and/or one with free slot. If not, it indicates
  that all resources (cca. 1GiB of memory) has been consumed, in that case just
  raise exception.
}
For i := Low(InfoSectionPtr^.DataSections) to High(InfoSectionPtr^.DataSections) do
  begin
    If InfoSectionPtr^.DataSections[i].ItemCount > 0 then
      begin
        // this section is used...
        If (InfoSectionPtr^.DataSections[i].ItemCount < fItemsPerSection) then
          // ...and is not full
          If SectionFirstFreeSlot < 0 then
            SectionFirstFreeSlot := i;
        // probe this section for this item
        ProbedSection := TSimpleSharedMemory.Create(NSI_SHAREDMEMORY_DATASECT_SIZE,GetDataSectionName(i));
        try
          ProbedItem := PNSIItemHeader(ProbedSection.Memory);
          For j := 1 to fItemsPerSection do
            begin
              If ProbedItem^.RefCount > 0 then
                If SameSHA1(ProbedItem^.Hash,fNameHash) then
                  begin
                    Inc(ProbedItem^.RefCount);
                    fDataSectionIndex := i;
                    fDataSection := ProbedSection;
                    fItemMemory := Pointer(ProbedItem);
                    Exit; // also breaks out of the for cycle
                  end;
              PtrAdvanceVar(Pointer(ProbedItem),fFullItemSize);
            end;
          FreeAndNil(ProbedSection);  // not called if the item was found
        except
          // in case something bad happens during probing
          FreeAndNil(ProbedSection);
          raise;
        end;
      end
    else
      begin
        // this section is unused
        If SectionFirstUnused < 0 then
          SectionFirstUnused := i;
      end;
  end;
{
  If here then the item was not found, add it as a new one.
  
  First try adding it into already used section, so we don't have to allocate
  new section.
}
If SectionFirstFreeSlot >= 0 then
  begin
    fDataSectionIndex := SectionFirstFreeSlot;
    ProbedSection := TSimpleSharedMemory.Create(NSI_SHAREDMEMORY_DATASECT_SIZE,GetDataSectionName(fDataSectionIndex));
    try
      ProbedItem := PNSIItemHeader(ProbedSection.Memory);
      For j := 1 to fItemsPerSection do
        begin
          If ProbedItem^.RefCount <= 0 then
            begin
              FillChar(ProbedItem^,fFullItemSize,0);
              ProbedItem^.RefCount := 1;
              ProbedItem^.Hash := fNameHash;
              fDataSection := ProbedSection;
              fItemMemory := Pointer(ProbedItem);
              Inc(InfoSectionPtr^.DataSections[fDataSectionIndex].ItemCount);
              Exit;
            end;
          PtrAdvanceVar(Pointer(ProbedItem),fFullItemSize);
        end;
      raise ENSIOutOfResources.CreateFmt('TNamedSharedItem.FindOrAllocateItem: No free item slot found in given section (%d).',[fDataSectionIndex]);
    except
      FreeAndNil(ProbedSection);
      raise;
    end;
  end
else If SectionFirstUnused >= 0 then
  begin
    fDataSectionIndex := SectionFirstUnused;
    fDataSection := TSimpleSharedMemory.Create(NSI_SHAREDMEMORY_DATASECT_SIZE,GetDataSectionName(fDataSectionIndex));
    try
      fItemMemory := fDataSection.Memory;
      PNSIItemHeader(fItemMemory)^.RefCount := 1;
      PNSIItemHeader(fItemMemory)^.Hash := fNameHash;
      InfoSectionPtr^.DataSections[fDataSectionIndex].ItemCount := 1;
      Exit;
    except
      FreeAndNil(fDataSection);
      raise;
    end;
  end;
raise ENSIOutOfResources.Create('TNamedSharedItem.FindOrAllocateItem: No free item slot found.');
end;

//------------------------------------------------------------------------------

procedure TNamedSharedItem.AllocateItem;
begin
// get info section, initialize it if necessary
fInfoSection := TSharedMemory.Create(NSI_SHAREDMEMORY_INFOSECT_SIZE,GetInfoSectionName);
fInfoSection.Lock;
try
  If PNSIInfoSection(fInfoSection.Memory)^.Flags and NSI_INFOSECT_FLAG_ACTIVE = 0 then
    begin
      // section not initialized, initialize it
      PNSIInfoSection(fInfoSection.Memory)^.Flags := NSI_INFOSECT_FLAG_ACTIVE;
      FillChar(PNSIInfoSection(fInfoSection.Memory)^.DataSections,SizeOf(TNSIDataSectionsArray),0);
    end;
  FindOrAllocateItem;  
finally
  fInfoSection.Unlock;
end;
If (fDataSectionIndex < 0) or not Assigned(fDataSection) or not Assigned(fItemMemory) then
  raise ENSIItemAllocationError.Create('TNamedSharedItem.AllocateItem: No free item slot found.');
fPayloadMemory := Addr(PNSIItemHeader(fItemMemory)^.Payload);
end;

//------------------------------------------------------------------------------

procedure TNamedSharedItem.DeallocateItem;
begin
If Assigned(fInfoSection) then
  begin
    fInfoSection.Lock;
    try
      If Assigned(fDataSection) then
        begin
          Dec(PNSIItemHeader(fItemMemory)^.RefCount);
          If PNSIItemHeader(fItemMemory)^.RefCount <= 0 then
            begin
              PNSIItemHeader(fItemMemory)^.RefCount := 0;
              Dec(PNSIInfoSection(fInfoSection.Memory)^.DataSections[fDataSectionIndex].ItemCount);
            end;
          FreeAndNil(fDataSection);
        end;
    finally
      fInfoSection.Unlock;
    end;
    FreeAndNil(fInfoSection);
  end;
end;

//------------------------------------------------------------------------------

procedure TNamedSharedItem.Initialize(const Name: String; Size: TMemSize);
begin
fName := Name;
fNameHash := WideStringSHA1(StrToWide(fName));
If (Size > 0) and (Size <= NSI_SHAREDMEMORY_DATASECT_MAXITEMSIZE) then
  fSize := Size
else
  raise ENSIInvalidValue.CreateFmt('TNamedSharedItem.Initialize: Invalid item size (%d).',[Size]);
fInfoSection := nil;
fDataSectionIndex := -1;
fDataSection := nil;
fItemMemory := nil;
fPayloadMemory := nil;
{
  Get size of item with everything (header, padding, ...).

  It is part of section name and is also used for calculation of direct memory
  address of items within the shared memory section.
}
fFullItemSize := (TMemSize(SizeOf(TNSIItemHeader)) + fSize +
   TMemSize(Pred(NSI_SHAREDMEMORY_DATASECT_ALIGNMENT))) and not
  TMemSize(Pred(NSI_SHAREDMEMORY_DATASECT_ALIGNMENT));
{
  fItemsPerSection serves for comparison whether there is a free "slot" in
  given data section.
}
fItemsPerSection := NSI_SHAREDMEMORY_DATASECT_SIZE div fFullItemSize;
AllocateItem;
end;

//------------------------------------------------------------------------------

procedure TNamedSharedItem.Finalize;
begin
DeallocateItem;
end;

{-------------------------------------------------------------------------------
    TNamedSharedItem - public methods
-------------------------------------------------------------------------------}

constructor TNamedSharedItem.Create(const Name: String; Size: TMemSize);
begin
inherited Create;
Initialize(Name,Size);
end;

//------------------------------------------------------------------------------

destructor TNamedSharedItem.Destroy;
begin
Finalize;
inherited;
end;

end.
