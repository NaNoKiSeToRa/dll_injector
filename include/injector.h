#pragma once

#include <string>
#include <cstdint>
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

namespace injector
{
  namespace detail
  {
    __forceinline bool write(
      void* process_handle,
      uint64_t address,
      void* buffer,
      size_t size
    )
    {
      return WriteProcessMemory(
        process_handle,
        (void*)address,
        buffer,
        size,
        nullptr
      );
    }

    __forceinline void* allocate(
      void* process_handle,
      uint64_t address,
      size_t size,
      DWORD allocate_type,
      DWORD protection
    )
    {
      return VirtualAllocEx(
        process_handle,
        (void*)address,
        size,
        allocate_type,
        protection
      );
    }
  }

  // injects the dll into the specified process id
  void* inject(_In_ const std::string& dll_path, _In_ uint32_t pid)
  {
    // opens process with all permissions
    void* process_handle = OpenProcess(
      PROCESS_ALL_ACCESS,
      false,
      pid
    );

    if ( process_handle )
    {
      std::cout << '\n' << "successfully opened process" << '\n';
      HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
      if ( kernel32 )
      {
        // gets the address of 'LoadLibraryA()' function
        void* load_lib_address = GetProcAddress(
          kernel32,
          "LoadLibraryA"
        );

        // allocates a space in the process memory that is readable and writable
        void* alloc_memory = detail::allocate(
          process_handle,
          NULL,
          dll_path.size(),
          MEM_COMMIT,
          PAGE_READWRITE
        );

        if ( alloc_memory )
        {
          if ( detail::write(
            process_handle,
            (uint64_t)alloc_memory,
            (void*)dll_path.data(),
            dll_path.size()) )
          {
            std::cout << "process memory write was successful" << '\n';
          }

          // creates a thread in the target process that calls the 'LoadLibraryA()' function
          void* thread_handle = CreateRemoteThread(
            process_handle,
            nullptr,
            0,
            (LPTHREAD_START_ROUTINE)load_lib_address,
            alloc_memory,
            0,
            nullptr
          );

          if ( thread_handle )
          {
            // waits for the thread object to finish
            WaitForSingleObject(
              thread_handle,
              INFINITE
            );

            // frees up the allocated space
            VirtualFreeEx(
              process_handle,
              alloc_memory,
              0,
              MEM_RELEASE
            );

            // closes thread
            CloseHandle(thread_handle);

            // closes process
            CloseHandle(process_handle);
          }
        }
      }
    }
    return nullptr;
  }

  // returns the id of the specified process name
  uint32_t get_process_pid(_In_ const wchar_t* process_name, _Inout_ uint32_t& pid)
  {
    // creates a snapshot of current processes
    void* snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if ( snapshot )
    {
      PROCESSENTRY32 p_entry32{};
      ZeroMemory(&p_entry32, sizeof(p_entry32));
      p_entry32.dwSize = sizeof(p_entry32);

      // scrolls the processes in PROCESSENTRY32 a.k.a p_entry32
      if ( Process32First(snapshot, &p_entry32) )
      {
        do
        {
          // checks if the entry matches the target process
          if ( wcscmp(p_entry32.szExeFile, process_name) == 0 )
          {
            // if it matches, it assigns the entry id to pid variable
            pid = p_entry32.th32ProcessID;
            break;
          }
        }
        while ( Process32Next(snapshot, &p_entry32) );
      }
      // closes the snapshot
      CloseHandle(snapshot);
    }
    return pid;
  }
}
