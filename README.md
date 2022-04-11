# Insert Dylib tool

This is a side project to learn more about macho binary during my free time. The purpose of project is to insert dylib path into the macho binary load commands. The project is based on https://github.com/Tyilo/insert_dylib/blob/master/insert_dylib/main.c with the help of Python macholib from https://github.com/ronaldoussoren/macholib to make insert_dylib available in Python

So far, I only support ARM64 binary