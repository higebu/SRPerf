from abc import ABCMeta, abstractmethod


# An Experiment must extend this class.
class Experiment(metaclass=ABCMeta):
    @abstractmethod
    def run(self, *args):
        pass

# Factory for Experiment.
# Every Experiment should define its own factory method (and class).
class ExperimentFactory(metaclass=ABCMeta):
    @abstractmethod
    def build(self, *args):
        pass

class ExperimentOutput(metaclass=ABCMeta):
    @abstractmethod
    def getRequestedTxRate(self):
        pass

    @abstractmethod
    def getAverageDR(self):
        pass

    @abstractmethod
    def getStdDR(self):
        pass

    @abstractmethod
    def toString(self):
        pass

class ExperimentException(Exception):
    
    def __init__(self, message):
        super(Exception, self).__init__(message)
