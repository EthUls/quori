<?php

namespace App\Controller;

use App\Entity\Comment;
use App\Entity\Question;
use App\Form\CommentType;
use App\Form\QuestionType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class QuestionController extends AbstractController
{
    #[Route('/question/ask', name: 'ask_question')]
    public function ask(Request $request, EntityManagerInterface $em): Response
    {
        $question = new Question();

        $formQuestion = $this->createForm(QuestionType::class, $question);
        $formQuestion->handleRequest($request);

        if($formQuestion->isSubmitted() && $formQuestion->isValid()){
            $question->setNbResponse(0);
            $question->setRating(0);
            $question->setCreatedAt(new \DateTimeImmutable());

            
            $em->persist($question);
            $em->flush();
            
            
            $this->addFlash('success', 'Votre question à été ajoutée');
            return $this->redirectToRoute('home');
        }


        return $this->render('question/index.html.twig', ['form' => $formQuestion->createView()]);
    }
    #[Route('/question/{id}', name: 'show_question')]
    public function show(Request $request, Question $question, EntityManagerInterface $em) {

        $comment = new Comment();
        $commentForm = $this->createForm(CommentType::class, $comment);
        $commentForm->handleRequest($request);

        if ($commentForm->isSubmitted() && $commentForm->isValid()) {

            $comment->setCreatedAt(new \DateTimeImmutable());
            $comment->setRating(0);
            $comment->setQuestion($question);

            $question->setNbResponse($question->getNbResponse() + 1);

            $em->persist($comment);
            $em->flush();

            $this->addFlash('success', 'Votre réponse a bien été publiée');
            
            return $this->redirect($request->getUri());
        }

        return $this->render('question/show.html.twig', ['question' => $question, 'form' => $commentForm->createView()]);
    }

    #[Route('/question/rating/{id}/{score}', name: 'question_rating')] 
    public function rate(Request $request, Question $question, int $score, EntityManagerInterface $em) {

        // http://localhost:8000/question/3 => http://localhost:8000/question/3/1 => http://localhost:8000/question/3
        $question->setRating($question->getRating() + $score);
        // /question/3/1 => 4 + 1 = 5 Rating UP
        // /question/3/-1 => 4 + -1 = 3 Rating Down
        $em->flush();

        $referer = $request->server->get('HTTP_REFERER');
        return $referer ? $this->redirect($referer) : $this->redirectToRoute('home');
    }

}
