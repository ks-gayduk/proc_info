# ProcInfo 1.0
<p align="justify">Приложение, предназначено для мониторинга потребления ресурсов ЭВМ заданным процессом. Производится сбор следующей информации:</p>
Память:
<ul>
<li>размер рабочего набора;</li>
<li>использование виртуальной памяти;</li>
<li>размер выгружаемого системного пула;</li>
<li>размер невыгружаемого системного пула;</li>
<li>использование файла подкачки;</li>
<li>размер приватного набора.</li>
</ul>
Время ЦП:
<ul>
<li>время работы в режиме пользователя;</li>
<li>время работы в режиме ядра;</li>
<li>общее время использования процессора;</li>
<li>общая загрузка процессора заданным процессом.</li>
</ul>
Ввод-вывод:
<ul>
<li>количество операций чтения;</li>
<li>количество операций записи;</li>
<li>количество прочих операций ввода-вывода;</li>
<li>количество прочитанных байт;</li>
<li>количество записанных байт;</li>
<li>количество переданных байт в ходе прочих операций ввода-вывода.</li>
</ul>
<p align="justify">Для запуска приложения необходимо обладать правами администратора. Сразу после запуска, отображается вкладка Processes, на которой пользователь может выбрать процесс для наблюдения, а также задать требуемое время мониторинга и интервал опроса системной информации (шаг дискретизации).</p>
<p align="justify">При необходимости, список существующих в системе процессов может быть обновлен по нажатию кнопки Update. Процесс мониторинга запускается по нажатию кнопки Start, и автоматически завершается по истечении заданного времени мониторинга, либо по нажатию кнопки Stop.</p>
<p align="justify">Время начала и окончания мониторинга, а также фактическое (астрономическое) время процесса мониторинга отображаются в строке состояния.</p>
<img src="https://raw.githubusercontent.com/ks-gayduk/proc_info/master/screen/1_proc_list.png">
<p align="justify">По результатам мониторинга памяти, для каждого из наблюдаемых параметров отображается сводная информация:<br>
min(param) – минимальное значение;<br>
max(param) – максимальное значение;<br>
mean(param) – среднее значение.</p>
<img src="https://raw.githubusercontent.com/ks-gayduk/proc_info/master/screen/2_memory.png">
<p align="justify">Для таких параметров как время выполнения процесса в режиме пользователя, в режиме ядра, а также суммарное время использования процессора, отображается следующая сводная информация:<br>
beg(param) – начальное значение;<br>
end(param) – конечное значение;<br>
diff(param) – разность.<br>
Для загрузки процессора отображается минимальное, максимальное и среднее значения.</p>
<img src="https://raw.githubusercontent.com/ks-gayduk/proc_info/master/screen/3_cpu.png">
<p align="justify">Для параметров ввода-вывода отображаются начальные и конечные значения, а также их разность. Кроме того, выполняется усреднение по времени (ср. количество операций в секунду, ср. количество байт в секунду).</p>
<img src="https://raw.githubusercontent.com/ks-gayduk/proc_info/master/screen/4_io.png">
<p align="justify">По результатам мониторинга, программа генерирует файл с названием &lt;PID&gt;_stat.txt, где PID – идентификатор наблюдаемого процесса.<br>
В данном файле одна строка соответствует одному измерению всех наблюдаемых параметров. В строке параметры идут в следующем порядке:</p>
<ol>
<li>использование виртуальной памяти, байт;</li>
<li>рабочий набор, байт;</li>
<li>размер выгружаемого системного пула, байт;</li>
<li>размер невыгружаемого системного пула, байт;</li>
<li>использование файла подкачки, байт;</li>
<li>размер приватного набора, байт;</li>
<li>время работы в режиме пользователя, 100-наносекундные интервалы;</li>
<li>время работы в режиме ядра, 100-наносекундные интервалы;</li>
<li>количество операций чтения;</li>
<li>количество операций записи;</li>
<li>количество прочих операций ввода-вывода;</li>
<li>количество прочитанных байт;</li>
<li>количество записанных байт;</li>
<li>количество переданных байт в ходе прочих операций ввода-вывода;</li>
<li>загрузка процессора, %.</li>
</ol>
<p align="justify">На основании полученного файла, можно производить более детальную математическую и статистическую обработку собранных данных в таких пакетах как MATLAB, MatCAD и др.</p>
