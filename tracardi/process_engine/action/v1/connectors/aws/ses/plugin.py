from tracardi.service.notation.dot_template import DotTemplate
from tracardi.service.storage.driver import storage
from tracardi.service.plugin.runner import ActionRunner
from tracardi.service.plugin.domain.result import Result
from tracardi.service.plugin.domain.register import Plugin, Spec, MetaData, Form, FormGroup, FormField, FormComponent, \
    Documentation, PortDoc
from .model.model import Config
from ..sqs.model.model import AwsIamAuth
from aiobotocore.session import get_session
from email_validator import validate_email, EmailNotValidError


def validate(config: dict):
    return Config(**config)


class AwsSesAction(ActionRunner):
    credentials: AwsIamAuth
    config: Config
    _dot_template: DotTemplate

    async def set_up(self, init):
        config = validate(init)
        resource = await storage.driver.resource.load(config.source.id)

        self.config = config
        self.credentials = resource.credentials.get_credentials(self, output=AwsIamAuth)
        self._dot_template = DotTemplate()

    async def run(self, payload: dict, in_edge=None) -> Result:
        dot = self._get_dot_accessor(payload)
        message = self._dot_template.render(self.config.message.content.content, dot)
        recipient_emails = dot[self.config.message.recipient]
        recipient_emails = recipient_emails if isinstance(recipient_emails, list) else [recipient_emails]
        validate_email(self.config.sender_email)
        valid_recipient_emails = await self.get_valid_to_emails(recipient_emails)

        send_email_info = dict(
            FromEmailAddress=self.config.sender_email,
            FromEmailAddressIdentityArn='string',
            Destination={
                'ToAddresses': valid_recipient_emails,
            },
        )
        if self.config.message.content.type == "text/html":
            send_email_info['Content'] = {
                'Simple': {
                    'Subject': {
                        'Data': self.config.message.subject,
                    },
                    'Body': {
                        'Html': {
                            'Data': message,
                        }
                    }
                }
            }
        else:
            send_email_info['Content'] = {
                'Simple': {
                    'Subject': {
                        'Data': self.config.message.subject,
                    },
                    'Body': {
                        'Text': {
                            'Data': message,
                        }
                    }
                }
            }
        try:
            session = get_session()
            async with session.create_client('ses', region_name=self.config.region_name,
                                             aws_secret_access_key=self.credentials.aws_secret_access_key,
                                             aws_access_key_id=self.credentials.aws_access_key_id
                                             ) as client:
                result = await client.send_email(send_email_info)
                return Result(port="response", value=result)
        except Exception as e:
            return Result(port="error", value={"message": str(e)})

    async def get_valid_to_emails(self, recipient_emails):
        valid_recipient_emails = []
        for email in recipient_emails:
            try:
                validate_email(email)
                valid_recipient_emails.append(email)
            except EmailNotValidError:
                self.console.warning("Recipient e-mail {} is not valid email. This e-mail was skipped.".format(email))
                continue
        return valid_recipient_emails


def register() -> Plugin:
    return Plugin(
        start=False,
        spec=Spec(
            module=__name__,
            className='AwsSesAction',
            inputs=["payload"],
            outputs=["result", "error"],
            version='0.7.2',
            license="MIT",
            author="Ben Ullrich",
        ),
        metadata=MetaData(
            name='E-mail SES',
            desc='Sends a message using Amazon AWS SES',
            icon='aws',
            tags=['aws', 'email'],
            group=["Amazon Web Services (AWS)"],
            documentation=Documentation(
                inputs={
                    "payload": PortDoc(desc="This port takes payload object.")
                },
                outputs={
                    "result": PortDoc(desc="Returns result."),
                    "error": PortDoc(desc="Gets triggered if an error occurs.")
                }
            ),
            pro=True
        )
    )
