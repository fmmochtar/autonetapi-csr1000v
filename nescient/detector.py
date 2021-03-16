import schedule

from nescient.core import core

schedule.every(3).seconds.do(core)
