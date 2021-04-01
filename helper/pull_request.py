import os
from collections import defaultdict
from datetime import datetime


class PullRequest(object):
    def __init__(self, pull_request_data):
        self.__pull_request_data = pull_request_data

    @property
    def author_name(self):
        return self.__pull_request_data['author']['user']['displayName']

    @property
    def reviewers(self):
        return self.__pull_request_data['reviewers']

    @property
    def properties(self):
        return self.__pull_request_data.get('properties')

    @property
    def activities(self):
        return self.__pull_request_data.get('activities')

    @property
    def duration_until_merge(self):
        """Calculate time until creation point and close point for a pull request"""
        created_timestamp = self.__pull_request_data['createdDate']
        closed_timestamp = self.__pull_request_data['closedDate']

        created_date = datetime.fromtimestamp(created_timestamp / 1e3)
        closed_date = datetime.fromtimestamp(closed_timestamp / 1e3)
        delta = closed_date - created_date
        return delta.seconds

    @property
    def tasks_and_comments(self):
        """
        Get all the tasks and comments associated with the pull request.
        Both are organized as dictionary having the user name as a key and the number of tasks and comments as values
        :return: The tasks and comments associated with the pull request.
        """
        tasks = defaultdict(lambda: 0)
        comments = defaultdict(lambda: 0)

        if 'activities' not in self.__pull_request_data:
            return tasks, comments

        for activity in self.activities:
            if activity['action'] != 'COMMENTED':
                continue

            # count only comments which don't have associated tasks
            # for the ones which have an associated tasks, we'll count the tasks, anyway
            if not activity['comment']['tasks']:
                comments[activity['comment']['author']['displayName']] += 1

            for task in activity['comment']['tasks']:
                tasks[task['author']['displayName']] += 1

        return tasks, comments


class ReviewStatistics(object):
    """Calculate the statistics of reviews out of a dictionary of pull requests."""

    def __init__(self, pull_requests):
        self.pull_requests = pull_requests

        self.authors = defaultdict(lambda: 0)

        # a dictionary holding per user: the number of reviews, number of tasks, comments without tasks
        self.reviewers = defaultdict(lambda: [0, 0, 0])
        self.statistics = defaultdict(lambda: 0)
        self.tasks = defaultdict(lambda: 0)
        self.comments = defaultdict(lambda: 0)

        for pr in self.pull_requests:
            pull_request = PullRequest(pr)
            self.authors[pull_request.author_name.encode("utf-8")] += 1

            for reviewer in pull_request.reviewers:
                self.reviewers[(reviewer['user']['displayName']).encode("utf-8")][0] += 1

            tasks, comments = pull_request.tasks_and_comments
            for user, task_count in tasks.iteritems():
                self.reviewers[user.encode("utf-8")][1] += task_count

            for user, comment_count in comments.iteritems():
                self.reviewers[user.encode("utf-8")][2] += comment_count

            if not pull_request.properties:
                continue

            open_tasks_count = pull_request.properties.get('openTaskCount', 0)
            comment_count = pull_request.properties.get('commentCount', 0)
            resolved_task_count = pull_request.properties.get('resolvedTaskCount', 0)

            self.statistics['topTasksReview'] = max(self.statistics['topTasksReview'], open_tasks_count)
            self.statistics['commentCount'] += comment_count
            self.statistics['openTaskCount'] += open_tasks_count
            self.statistics['resolvedTaskCount'] += resolved_task_count
            self.statistics['noTaskReviews'] += (1 if resolved_task_count == 0 else 0)
            self.statistics['noCommentReviews'] += (1 if comment_count == 0 else 0)
            self.statistics['noIssueReviews'] += (1 if (resolved_task_count + comment_count) == 0 else 0)
            self.statistics['totalTimeUntilMerge'] += pull_request.duration_until_merge

    def get_top_authors(self, top_stats_count=1):
        """Get the top authors [all authors which submitted the same top number of reviews]
        :param top_stats_count: the number of top authors
        :return: a a list of tuples [author_name, submitted_reviews_count]
        """
        return sorted(self.authors.iteritems(), lambda x, y: cmp(x[1], y[1]), reverse=True)[:top_stats_count]

    def get_top_reviewers(self, top_stats_count=1):
        """Get the top reviewers [all reviewers which participated to the same top number of reviews]
        :param top_stats_count: the number of top reviewers
        :return: a list of tuples [reviewer_name, [number of reviews, number of tasks, bymber of comments]]
        """
        return sorted(self.reviewers.iteritems(), lambda x, y: cmp(x[1][0], y[1][0]), reverse=True)[:top_stats_count]

    def get_top_task_submitters(self, top_stats_count=1):
        """Get the top task submitters to the pull requests
        :param top_stats_count: the number of top pull request task submitters
        :return: a list of tuples [reviewer_name, [number of reviews, number of tasks, bymber of comments]]
        """
        return sorted(self.reviewers.iteritems(), lambda x, y: cmp(x[1][1], y[1][1]), reverse=True)[:top_stats_count]

    def get_top_comment_submitters(self, top_stats_count=1):
        """Get the top comment submitters to the pull requests
        :param top_stats_count: the number of top pull request comment submitters
        :return: a list of tuples [reviewer_name, [number of reviews, number of tasks, number of comments]]
        """
        return sorted(self.reviewers.iteritems(), lambda x, y: cmp(x[1][2], y[1][2]), reverse=True)[:top_stats_count]

    def get_average_stats(self):
        """Get the average stats: average reviews per author, average tasks per review,
        average comments per review, average time until merge"""

        # the use of 1.0 multiplication ensures the floating point division
        avg_review_per_author = 1.0 * self.get_reviews_count() / len(self.authors)

        avg_tasks_per_review = 1.0 * self.statistics['resolvedTaskCount'] \
            / (self.get_reviews_count() - self.statistics['noTaskReviews'])

        avg_comments_per_review = 1.0 * self.statistics['commentCount'] \
            / (self.get_reviews_count() - self.statistics['noCommentReviews'])

        avg_time_until_merge = 1.0 * self.statistics['totalTimeUntilMerge'] / self.get_reviews_count()

        return avg_review_per_author, avg_tasks_per_review, avg_comments_per_review, avg_time_until_merge

    def get_blank_stats(self):
        """Get blank stats
        :return: % from total reviews of reviews w/o tasks, reviews w/o comments, reviews w/o tasks or comments"""

        # the use of .0 multiplication ensures the floating point division
        no_tasks_review_percent = 100.0 * self.statistics['noTaskReviews'] / self.get_reviews_count()
        no_comments_review_percent = 100.0 * self.statistics['noCommentReviews'] / self.get_reviews_count()
        no_issue_review_percent = 100.0 * self.statistics['noIssueReviews'] / self.get_reviews_count()
        return no_tasks_review_percent, no_comments_review_percent, no_issue_review_percent

    def get_reviews_count(self):
        """Get the number of reviews."""

        return len(self.pull_requests)

    def print_summary(self, top_stats_count=10):
        """Print review statistics summary.
        :param top_stats_count: the count of top statistics (e.g. reviewers/authors)
        """

        print '############################ Code review statistics ############################'

        if self.get_reviews_count() == 0:
            print 'No reviews available'
        else:
            avg_review_per_author, avg_tasks_per_review, avg_comments_per_review, avg_time_until_merge = \
                self.get_average_stats()
            print 'Total number of reviews                          = {0}'.format(self.get_reviews_count())
            print 'Average number of reviews per author             = {0:.0f}'.format(avg_review_per_author)
            print 'Average number of tasks per review               = {0:.0f}'.format(avg_tasks_per_review)
            print 'Average number of comments per review            = {0:.0f}'.format(avg_comments_per_review)
            print 'Average time until merge                         = {0:.0f} seconds'.format(avg_time_until_merge)

            no_tasks_review_percent, no_comments_review_percent, no_issue_review_percent = self.get_blank_stats()
            print 'Number of reviews with zero tasks                = {0:.0f}%'.format(no_tasks_review_percent)
            print 'Number of reviews with zero comments             = {0:.0f}%'.format(no_comments_review_percent)
            print 'Number of reviews with zero tasks and comments   = {0:.0f}%'.format(no_issue_review_percent)
            print os.linesep

            print 'Top {0} author(s):'.format(top_stats_count)
            for user, top_stats in self.get_top_authors(top_stats_count):
                print '\t{0} - {1} pull requests [{2:.0f}%]'.format(
                    user, top_stats, 100.0 * top_stats / self.get_reviews_count())

            print os.linesep
            print 'Top {0} reviewer(s):'.format(top_stats_count)
            for user, top_stats in self.get_top_reviewers(top_stats_count):
                print '\t{0} - {1} reviews [{2:.0f}%]'.format(
                    user, top_stats[0], 100.0 * top_stats[0] / self.get_reviews_count())

            print os.linesep
            print 'Top {0} task submitters:'.format(top_stats_count)
            for user, top_stats in self.get_top_task_submitters(top_stats_count):
                print '\t{0} - {1} tasks [{2:.0f}%] - {3:.2f} tasks/review'.format(
                    user,
                    top_stats[1],
                    100.0 * top_stats[1] / self.statistics['resolvedTaskCount'],
                    (1.0 * top_stats[1] / self.reviewers[user][0]) if self.reviewers[user][0] != 0 else 0
                )

            print os.linesep
            print 'Top {0} comment submitters:'.format(top_stats_count)
            for user, top_stats in self.get_top_comment_submitters(top_stats_count):
                # the number of comments w/o an associated task
                comments_no_tasks_count = (self.statistics['commentCount'] - self.statistics['resolvedTaskCount'])
                print '\t{0} - {1} comments [{2:.0f}%] - {3:.2f} comments/review'.format(
                    user,
                    top_stats[2],
                    (100.0 * top_stats[2] / comments_no_tasks_count) if comments_no_tasks_count != 0 else 0,
                    (1.0 * top_stats[2] / self.reviewers[user][0]) if self.reviewers[user][0] != 0 else 0
                )

        print '############################ End of code review statistics ############################'
