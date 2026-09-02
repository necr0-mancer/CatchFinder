# CatchFinder

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-9.0%2B-blue.svg)](https://hex-rays.com/ida-pro)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com)
[![Language](https://img.shields.io/badge/language-Python%203-green.svg)](https://www.python.org)
[![Target](https://img.shields.io/badge/target-PE%20(x64)-orange.svg)](https://github.com)

IDA Pro plugin that parses **FH4** (`__CxxFrameHandler4`) C++ exception-handling metadata
and lists the addresses of every `catch` handler in the selected function.

The full chain it walks:

```
RUNTIME_FUNCTION (.pdata)
    -> UNWIND_INFO
        -> ExceptionData
            -> FuncInfo4 (header, compressed)
                -> dispTryBlockMap
                    -> TryBlockMap4
                        -> dispHandlerArray
                            -> HandlerMap4
                                -> dispOfHandler     <- absolute address of the catch funclet
```

## Features

- Finds `TryBlockMap4`, `HandlerMap4`, decodes FH4 *compressed integers*
- Displays `ExceptionHandler`, `ExceptionData`, `dispOfHandler` in a **colored** chooser window
- Supports chained unwind (`UNW_FLAG_CHAININFO`)
- Skips non-exception functions
- Menu entry: **Edit → Plugins → CatchFinder**, hotkey **Ctrl+Shift+C**

## Installation

1. Copy `catchfinder_plugin.py` into `<IDADIR>/plugins/`
2. Restart IDA Pro
3. Open a 64-bit PE (`/EHa` or `/EHs`, VS2019+ / VS2022) binary
4. Put cursor on a C++ function, press **Ctrl+Shift+C** or use **Edit → Plugins → CatchFinder**

## Usage

1. Place the caret inside a C++ function with `try`/`catch`
2. Run the plugin — a chooser opens with three columns:
   - **ExceptionHandler** — usually `__CxxFrameHandler4`
   - **ExceptionData** — start of `FuncInfo4`
   - **dispOfHandler(catch-block)** — the actual `catch` code address

   Colors: orange-ish = handler, light orange = data, **purple = catch address**
3. Select a row → *Jump to* → pick which address to visit

## Requirements

- IDA Pro **9.0+** (IDAPython plugin API, `PLUGIN_ENTRY`, `Choose` with `OnGetLineAttr`)
- 64-bit PE binaries with FH4 metadata (MSVC `/d2FH4` / default since VS2019 for x64)

## Notes

- 32-bit IDBs are skipped with a warning (FH4 is for x64)
- The plugin does **not** modify any bytes — read-only parser
- `result` accumulates per run; the chooser lists everything found in one pass

## Limitations

- `UnwindMap4` / `IPtoStateMap4` are parsed only enough to locate `TryBlockMap4`; their entries are **not** decoded
- Continuation addresses in `HandlerType4` are skipped (not catch addresses)
- Only `dispOfHandler` (the catch funclet) is reported — `dispType`/`dispCatchObj` are consumed but not displayed

---

# CatchFinder (RU)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-9.0%2B-blue.svg)](https://hex-rays.com/ida-pro)

Плагин IDA Pro, который парсит метаданные **FH4** (`__CxxFrameHandler4`) и выводит адреса всех `catch`-обработчиков выбранной функции.

Полный путь:

```
RUNTIME_FUNCTION (.pdata)
    -> UNWIND_INFO
        -> ExceptionData
            -> FuncInfo4 (заголовок, сжатие)
                -> dispTryBlockMap
                    -> TryBlockMap4
                        -> dispHandlerArray
                            -> HandlerMap4
                                -> dispOfHandler     <- абсолютный адрес funclet'а catch
```

## Возможности

- Находит `TryBlockMap4`, `HandlerMap4`, декодирует FH4 *compressed integers*
- Показывает `ExceptionHandler`, `ExceptionData`, `dispOfHandler` в **цветном** окне выбора
- Поддерживает `UNW_FLAG_CHAININFO` (вложенные `RUNTIME_FUNCTION`)
- Пропускает функции без исключений
- Меню: **Edit → Plugins → CatchFinder**, горячая клавиша **Ctrl+Shift+C**

## Установка

1. Скопируйте `catchfinder_plugin.py` в `<IDADIR>/plugins/`
2. Перезапустите IDA Pro
3. Откройте 64-битный PE (MSVC `/EHa` или `/EHs`, VS2019+ / VS2022)
4. Поставьте курсор на C++ функцию, нажмите **Ctrl+Shift+C** или **Edit → Plugins → CatchFinder**

## Использование

1. Поставьте каретку внутрь C++ функции с `try`/`catch`
2. Запустите плагин — появится окно с тремя колонками:
   - **ExceptionHandler** — обычно `__CxxFrameHandler4`
   - **ExceptionData** — начало `FuncInfo4`
   - **dispOfHandler(catch-block)** — адрес кода `catch`

   Цвета: оранжевый = handler, светло-оранжевый = data, **фиолетовый = адрес catch**
3. Выберите строку → *Jump to* → выберите, куда перейти

## Требования

- IDA Pro **9.0+** (IDAPython `PLUGIN_ENTRY`, `Choose` с `OnGetLineAttr`)
- 64-битные PE с FH4 метаданными (MSVC `/d2FH4` / по умолчанию начиная с VS2019 для x64)

## Примечания

- 32-битные IDB'ы пропускаются с предупреждением (FH4 для x64)
- Плагин **ничего не изменяет** — только читает
- `result` накапливается за один прогон; окно показывает всё найденное

## Ограничения

- `UnwindMap4` / `IPtoStateMap4` разбираются настолько, чтобы дойти до `TryBlockMap4`; их записи **не** декодируются
- Continuation-адреса в `HandlerType4` пропускаются (не являются catch-адресами)
- Плагин показывает только `dispOfHandler` — `dispType`/`dispCatchObj` читаются, но не отображаются

---

## License

MIT — see [LICENSE](LICENSE).
