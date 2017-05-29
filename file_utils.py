import os


class FileUtils:

    def __init__(self):
        return

    @staticmethod
    def walk_in_directory(directory, callback):
        """
        recursively run through all the directories and get files
        for each file call the callback function with added filename and its directory
        :param directory: directory to start with searching
        :param callback: this function will be called with file directory
        :return:
        """

        for root, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                file_dir = os.path.join(root, filename)
                # call the callback with file dir
                callback(file_dir)
        return

    @staticmethod
    def read_data_from_file(filename):
        """
        Read whole data from the file
        :param filename:
        :return: if successfull returns string else None
        """
        with open(name=filename, mode='r') as file:
            data = file.read()
        return data

    @staticmethod
    def write_data_to_file(filename, data):
        """
        Read whole data from the file
        :param filename:
        :param data to write file
        :return:
        """
        with open(name=filename, mode='w') as file:
            file.write(data)
        return


