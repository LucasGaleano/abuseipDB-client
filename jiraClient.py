from jira import JIRA

class JiraClient():


    def __init__(self, server, email, token):
        jira_options = {'server': server}
        self.jira = JIRA(options=jira_options, basic_auth=(email, token))


    def create_ticket(self, project, summary, description,priority="Medium"):
        new_issue = self.jira.create_issue(
            project=project, 
            summary=summary,
            description=description, 
            priority={'name': priority},
            issuetype={'name': 'Task'}
        )
        return new_issue

    def search_tickets(self, searchSQL):
        issues = self.jira.search_issues(searchSQL)
        return issues

    def search_ticket_by_ip(self, project, ip):
        tickets =  self.search_tickets(f'project={project} AND summary~"{ip}" AND statusCategory != Done')
        ticket = next((i for i in tickets if f"[{ip}]" in i.fields.summary ), None)
        return ticket


    def add_comment(self, ticket, comment):
        self.jira.add_comment(ticket, comment)
        print(f'comment created on issue: {issue.key}')


    def update_ticket(self, ip, description, priority, project):
        formatdescription = "\n".join(f"- *{k}*: {v}" for k, v in description.items())
        ticket = self.search_ticket_by_ip(project,ip)
        if ticket:
            ticket.update(fields={'description': formatdescription, 'priority': {'name': priority}})
            status = {"action": "update"}
        else:
            ticket = self.create_ticket('IRM',f"[{ip}] on blacklist", description=formatdescription,priority=priority)
            status =  {"action": "created"}
        return status | {'Key':ticket.key, 'projectKey':ticket.fields.project.key, 'projectID':ticket.fields.project.id}
