@echo off
pushd "C:\Users\%USERNAME%\Scripts\rgb-scheduler"
start "" pythonw -m rgb_scheduler.scheduler -w
popd