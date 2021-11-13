#include "../include/injector.h"
using namespace injector;

int main()
{
  std::string dll_path;
  std::wstring process_name;

  std::cout << "dll path: ";
  std::cin >> dll_path;

  std::cout << "process name: ";
  std::wcin >> process_name;

  uint32_t pid{};
  pid = get_process_pid(process_name.c_str(), pid);

  inject(dll_path, pid);
}

